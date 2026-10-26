use std::{sync::OnceLock, time::Duration};

use backoffice::interval;
use rootcause::{Report, Result};

async fn before_start() -> Result<()> {
    println!("this ran before starting my_task");

    Ok(())
}

async fn after_finish() -> Result<()> {
    println!("this ran after finishing my_task");

    Ok(())
}

async fn error_handler(err: Report) {
    println!("encountered error with my_task: {err:?}");
}

struct MyTaskContext {
    name: String
}

static MY_TASK_CONTEXT: OnceLock<MyTaskContext> = OnceLock::new();

#[interval(secs = 1)]
#[before_start(before_start)]
#[after_finish(after_finish)]
#[on_error(error_handler)]
async fn my_task() -> Result<()> {
    let context = MY_TASK_CONTEXT.wait();

    println!("my_task was run!");

    bail!("this is to test error handling");
}

#[tokio::main]
async fn main() {
    my_task.start();

    println!("started running task");

    tokio::time::sleep(Duration::from_secs(3)).await;

    my_task.stop();
}
