- Use time gap between packet and its ack to determine ``fix_timestamp``
- Concatenate traces in the same directory to form one "virtual" trace
- Evaluate trace timestamp quality by looking at the gaps between packet and its
  ack.
- Merge multiple traces into one.
