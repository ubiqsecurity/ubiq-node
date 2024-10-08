class BillingEventsProcessor {

  intervalId;
  billing_events;

  constructor(web_services, be, configuration) {
    this.web_services = web_services;
    this.billing_events = be;
    this.configuration = configuration;
    this.interval = this.configuration.event_reporting_wake_interval * 1000;
    let t = new Date();
    this.flush_timestamp = t.setSeconds(t.getSeconds() + this.configuration.event_reporting_flush_interval);

    this.intervalId = setInterval(this.processEvents, this.interval, this);
  }

  async processEvents(be) {
    try {

      let count = be.billing_events.getEventCount();
      if (be.billing_events != undefined) {
        if ((count >= be.configuration.event_reporting_minimum_count) ||
          (be.flush_timestamp < new Date())) {

          // data is an array of objects, not a string
          const data = await be.billing_events.getAndResetSerializedData()
          const results = be.web_services.sendBillingAsync(data);
          let t = new Date();
          be.flush_timestamp = t.setSeconds(t.getSeconds() + be.configuration.event_reporting_flush_interval);
        }
      }
    } catch (ex) {
      console.log(`Process billing event failure: ${ex}`)
    }
  }

  async close() {
    clearInterval(this.intervalId);

    try {
      const data = await this.billing_events.getAndResetSerializedData();
      await this.web_services.sendBillingAsync(data);
    } catch (ex) {
      console.log(`Process billing event failure: ${ex}`)
    }
  }
}



module.exports = {
  BillingEventsProcessor,
};
