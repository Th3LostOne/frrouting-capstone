# MBB Multiple Robot Movement Results

- Completed attachments: 96/96.
- Correct observer mappings at batch checkpoints: 96/96.
- Correct observer mappings at the final checkpoint: 6/6.
- Type 2 origin event estimates: {'advertise MAC-only': 96, 'withdraw MAC-only': 96, 'withdraw MAC/IP': 95, 'advertise MAC/IP': 95}.
- Learning ARP send errors: 0 (see the move log for each error).
- Matching Zebra duplicate detection log entries: 18.
- Duplicate flags observed at checkpoints: 162.
- Observed BGP session drops: 0 across 10/10 tracked peers.

Batch checkpoints verify selected locations after the configured dwell. Transient state between checkpoints may go unobserved. The origin estimate groups matching copies across spines within each batch. DAD freeze policy is recorded separately from observed duplicate state. Use the captures and router logs to investigate mismatches.


## Make-before-break evidence

- Verified attachment and announcement ordering in 96 moves.
- Gateway ARP observed on the new access port before the old link went down in 96 moves.
- New-leaf originating advertisement observed at a spine before the old link went down in 96 moves.
- Recorded 421 observer samples and 0 query errors.

The attachment overlap uses a Linux active-backup bond. Its IP and MAC stay on bond0. The old and new links can receive during overlap, while the new link is selected for transmission. Overlap samples accept either attached VTEP, and batch checkpoints require the destination VTEP. Timing records bracket commands and queries. The leaf ARP captures verify the learning stimulus on the new access port. Snapshot and polling coverage can miss short-lived state changes.
