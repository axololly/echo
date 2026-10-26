use std::{sync::{Arc, atomic::{AtomicU64, Ordering}}, time::Duration};

use backoffice::interval;
use rootcause::{Report, Result, bail};

async fn error_handler(err: Report) {
    println!("encountered error with my_task: {err:?}");
}

#[derive(Clone)]
struct MyTaskContext {
    count: Arc<AtomicU64>
}

#[interval(secs = 1)]
#[rename(MyTask)]
#[on_error(error_handler)]
async fn my_task(ctx: MyTaskContext) -> Result<()> {
    let iter = ctx.count.fetch_add(1, Ordering::Relaxed);

    println!("my_task was run! (iteration: {iter})");

    bail!("this is to test error handling");
}

#[tokio::main]
async fn main() {
    let ctx = MyTaskContext {
        count: Arc::new(AtomicU64::new(0))
    };

    let task = MyTask::start(ctx.clone());

    println!("started running task");

    tokio::time::sleep(Duration::from_secs(3)).await;

    task.stop();

    println!("count: {}", ctx.count.load(Ordering::Relaxed));
}
