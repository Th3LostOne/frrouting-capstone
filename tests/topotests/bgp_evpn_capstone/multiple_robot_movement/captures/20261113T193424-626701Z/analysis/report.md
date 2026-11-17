# Multiple Robot Movement Results

- Completed attachments: 48/48.
- Correct observer mappings at batch checkpoints: 47/48.
- Correct observer mappings at the final checkpoint: 6/6.
- Type 2 origin event estimates: {'withdraw MAC/IP': 44, 'withdraw MAC-only': 47, 'advertise MAC-only': 47, 'advertise MAC/IP': 42}.
- Learning ARP errors: 10 (see the move log for each error).
- Matching Zebra duplicate detection log entries: 0.
- Duplicate flags observed at checkpoints: 0.
- Observed BGP session drops: 0 across 10/10 tracked peers.
- Batch 6 mismatches: host11 (expected 10.0.0.3, saw None).
- host11 also had a learning ARP error in batch 6.
- The spine captures show no originating Type 2 advertisement from leaf3 for host11 in batch 6.

Batch checkpoints verify selected locations after the configured dwell. Transient state between checkpoints may go unobserved. The origin estimate groups matching copies across spines within each batch. DAD freeze policy is recorded separately from observed duplicate state. Use the captures and router logs to investigate mismatches.
