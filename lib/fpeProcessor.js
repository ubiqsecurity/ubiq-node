class FpeProcessor {
    constructor(fpeTransactions, secondsToProcess) {
        this.fpeTransactions = fpeTransactions;
        this.interval = secondsToProcess * 1000;
        // _taskTimer = new Timer(interval);
        // _taskTimer.Elapsed += OnTimedEvent;
        // _taskTimer.AutoReset = true;
    }
}

module.exports = {
    FpeProcessor,
};
