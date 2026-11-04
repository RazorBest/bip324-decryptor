use rtrb::{Producer, PushError};

pub fn producer_blocking_push<T>(producer: &mut Producer<T>, mut value: T) {
    while let Err(PushError::Full(failed)) = producer.push(value) {
        value = failed;
    }
}
