use echo_tasks::interval;

#[interval(hours = 6)]
pub async fn clean_up_unused_session_keys() -> () {
    // ...
}
