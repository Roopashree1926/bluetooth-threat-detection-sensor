use crate::models::BluetoothEvent;

pub trait Pattern {

    fn name(&self) -> &'static str;

    fn process(&mut self, event: &BluetoothEvent);

}