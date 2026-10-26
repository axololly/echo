use crate::task::RunningTask;

#[derive(Clone, Default)]
pub struct TaskManager {
    tasks: Vec<RunningTask>
}

impl TaskManager {
    pub fn new() -> Self {
        Self::default()
    }

    impl
}
