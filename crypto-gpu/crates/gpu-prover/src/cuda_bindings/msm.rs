use super::*;

// SYSCOIN: A successful allocation must have an owner before either subsequent
// fallible step runs. Only a fully initialized owner is published to a context.
pub(crate) struct MsmBases<A: MsmApi = CudaMsmApi> {
    api: A,
    ptr: *mut c_void,
    len: usize,
    initialized: bool,
}

pub(crate) trait MsmApi {
    fn allocate(&self, len: usize) -> GpuResult<*mut c_void>;
    fn copy(&self, ptr: *mut c_void, source: &[u8]) -> GpuResult<()>;
    fn setup(&self) -> GpuResult<()>;
    fn free(&self, ptr: *mut c_void) -> GpuResult<()>;
    fn teardown(&self) -> GpuResult<()>;
}

pub(crate) struct CudaMsmApi(pub(crate) usize);

impl MsmApi for CudaMsmApi {
    fn allocate(&self, len: usize) -> GpuResult<*mut c_void> {
        let mut ptr = std::ptr::null_mut();
        // SAFETY: CUDA initializes this output pointer on successful allocation.
        let result = unsafe { bc_malloc(&mut ptr, len as u64) };
        if result != 0 {
            return Err(GpuError::CreateContextErr(result));
        }
        Ok(ptr)
    }

    fn copy(&self, ptr: *mut c_void, source: &[u8]) -> GpuResult<()> {
        // SAFETY: The allocation has source.len() bytes and source remains live.
        // The pinned backend uses cudaMemcpy, not cudaMemcpyAsync.
        let result = unsafe { bc_memcpy(ptr, source.as_ptr().cast(), source.len() as u64) };
        if result != 0 {
            return Err(GpuError::CreateContextErr(result));
        }
        Ok(())
    }

    fn setup(&self) -> GpuResult<()> {
        // SAFETY: The caller selected this device. The pinned backend sets kernel
        // attributes only, so a failed attempt owns no separate setup allocation.
        let result = unsafe { msm_set_up() };
        if result != 0 {
            return Err(GpuError::CreateContextErr(result));
        }
        Ok(())
    }

    fn free(&self, ptr: *mut c_void) -> GpuResult<()> {
        set_device(self.0)?;
        // SAFETY: This owner releases its unique successful CUDA allocation once.
        let result = unsafe { bc_free(ptr) };
        if result != 0 {
            return Err(GpuError::MemFreeErr(result));
        }
        Ok(())
    }

    fn teardown(&self) -> GpuResult<()> {
        // SAFETY: Called only after successful setup and after the owning context
        // synchronized all streams. The pinned implementation is currently a no-op.
        let result = unsafe { msm_tear_down() };
        if result != 0 {
            return Err(GpuError::DestroyContextErr(result));
        }
        Ok(())
    }
}

impl<A: MsmApi> MsmBases<A> {
    pub(crate) fn initialize(
        slot: &mut Option<Self>,
        api: A,
        source: &[u8],
        len: usize,
    ) -> GpuResult<()> {
        if slot.is_some() {
            return Err(GpuError::MsmAlreadyInitialized);
        }
        let ptr = api.allocate(source.len())?;
        let mut pending = Self {
            api,
            ptr,
            len,
            initialized: false,
        };
        pending.api.copy(pending.ptr, source)?;
        pending.api.setup()?;
        pending.initialized = true;
        *slot = Some(pending);
        Ok(())
    }

    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl<A: MsmApi> Drop for MsmBases<A> {
    fn drop(&mut self) {
        // SYSCOIN: Pending initialization has no asynchronous reader. Once
        // published, the context suppresses automatic field destruction until
        // its streams synchronize, including when its Drop unwinds on an error.
        self.api.free(self.ptr).expect("couldn't free MSM bases");
        if self.initialized {
            self.api.teardown().expect("couldn't tear down MSM");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone)]
    struct MockApi {
        events: Rc<RefCell<Vec<&'static str>>>,
        fail: Option<&'static str>,
    }

    impl MockApi {
        fn step(&self, event: &'static str) -> GpuResult<()> {
            self.events.borrow_mut().push(event);
            if self.fail == Some(event) {
                Err(GpuError::CreateContextErr(1))
            } else {
                Ok(())
            }
        }
    }

    impl MsmApi for MockApi {
        fn allocate(&self, _: usize) -> GpuResult<*mut c_void> {
            self.step("allocate")?;
            Ok(std::ptr::NonNull::<u8>::dangling().as_ptr().cast())
        }
        fn copy(&self, _: *mut c_void, _: &[u8]) -> GpuResult<()> {
            self.step("copy")
        }
        fn setup(&self) -> GpuResult<()> {
            self.step("setup")
        }
        fn free(&self, _: *mut c_void) -> GpuResult<()> {
            self.step("free")
        }
        fn teardown(&self) -> GpuResult<()> {
            self.step("teardown")
        }
    }

    #[test]
    fn allocation_failure_publishes_nothing_and_does_not_free() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let api = MockApi {
            events: events.clone(),
            fail: Some("allocate"),
        };
        let mut slot = None;
        assert!(MsmBases::initialize(&mut slot, api, &[1, 2], 1).is_err());
        assert!(slot.is_none());
        assert_eq!(*events.borrow(), ["allocate"]);
    }

    #[test]
    fn copy_and_setup_failure_roll_back_without_teardown_and_allow_retry() {
        for fail in ["copy", "setup"] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let api = MockApi {
                events: events.clone(),
                fail: Some(fail),
            };
            let mut slot = None;
            assert!(MsmBases::initialize(&mut slot, api, &[1, 2], 1).is_err());
            assert!(slot.is_none());
            let expected = if fail == "copy" {
                vec!["allocate", "copy", "free"]
            } else {
                vec!["allocate", "copy", "setup", "free"]
            };
            assert_eq!(*events.borrow(), expected);
            events.borrow_mut().clear();
            let api = MockApi {
                events: events.clone(),
                fail: None,
            };
            MsmBases::initialize(&mut slot, api, &[1, 2], 1).unwrap();
            assert_eq!(slot.as_ref().unwrap().len(), 1);
            drop(slot);
            assert_eq!(
                *events.borrow(),
                ["allocate", "copy", "setup", "free", "teardown"]
            );
        }
    }

    #[test]
    fn duplicate_initialization_preserves_the_original_owner() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let api = MockApi {
            events: events.clone(),
            fail: None,
        };
        let mut slot = None;
        MsmBases::initialize(&mut slot, api.clone(), &[1, 2], 1).unwrap();
        let original = slot.as_ref().unwrap().ptr();
        events.borrow_mut().clear();
        assert!(matches!(
            MsmBases::initialize(&mut slot, api, &[3, 4], 2),
            Err(GpuError::MsmAlreadyInitialized)
        ));
        assert_eq!(slot.as_ref().unwrap().ptr(), original);
        assert_eq!(slot.as_ref().unwrap().len(), 1);
        assert!(events.borrow().is_empty());
        drop(slot);
        assert_eq!(*events.borrow(), ["free", "teardown"]);
    }

    #[test]
    fn unwinding_before_sync_does_not_free_published_device_memory() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let api = MockApi {
            events: events.clone(),
            fail: None,
        };
        // SYSCOIN: This is the same guard used by GpuContext when synchronization
        // fails. Keeping device storage is safer than freeing a pending reader.
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut published = std::mem::ManuallyDrop::new(None);
            MsmBases::initialize(&mut published, api, &[1, 2], 1).unwrap();
            panic!("simulated synchronization failure");
        }));
        assert!(failed.is_err());
        assert_eq!(*events.borrow(), ["allocate", "copy", "setup"]);
    }
}
