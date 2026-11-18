# Multiple Robot Movement Results

- Completed attachments: 96/96.
- Correct observer mappings at batch checkpoints: 96/96.
- Correct observer mappings at the final checkpoint: 6/6.
- Type 2 origin event estimates: {'withdraw MAC/IP': 96, 'withdraw MAC-only': 96, 'advertise MAC-only': 96, 'advertise MAC/IP': 96}.
- Learning ARP errors: 0 (see the move log for each error).
- Matching Zebra duplicate detection log entries: 0.
- Duplicate flags observed at checkpoints: 0.
- Observed BGP session drops: 0 across 10/10 tracked peers.

Batch checkpoints verify selected locations after the configured dwell. Transient state between checkpoints may go unobserved. The origin estimate groups matching copies across spines within each batch. DAD freeze policy is recorded separately from observed duplicate state. Use the captures and router logs to investigate mismatches.
