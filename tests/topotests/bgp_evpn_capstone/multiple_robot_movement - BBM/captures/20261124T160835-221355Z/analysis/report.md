# Multiple Robot Movement Results

- Completed attachments: 96/96.
- Correct observer mappings at batch checkpoints: 94/96.
- Correct observer mappings at the final checkpoint: 6/6.
- Type 2 origin event estimates: {'withdraw MAC/IP': 92, 'withdraw MAC-only': 94, 'advertise MAC-only': 94, 'advertise MAC/IP': 92}.
- Learning ARP errors: 6 (see the move log for each error).
- Matching Zebra duplicate detection log entries: 1.
- Duplicate flags observed at checkpoints: 2.
- Observed BGP session drops: 0 across 10/10 tracked peers.
- Batch 2 mismatches: host11 (expected 10.0.0.3, saw None).
- host11 also had a learning ARP error in batch 2.
- The spine captures show no originating Type 2 advertisement from leaf3 for host11 in batch 2.
- Batch 4 mismatches: host12 (expected 10.0.0.1, saw None).
- host12 also had a learning ARP error in batch 4.
- The spine captures show no originating Type 2 advertisement from leaf1 for host12 in batch 4.

Batch checkpoints verify selected locations after the configured dwell. Transient state between checkpoints may go unobserved. The origin estimate groups matching copies across spines within each batch. DAD freeze policy is recorded separately from observed duplicate state. Use the captures and router logs to investigate mismatches.
