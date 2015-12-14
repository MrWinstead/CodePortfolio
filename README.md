# CodePortfolio
  Hello, I am Mike Winstead and I'd like to present the following repository as
a sample of some of the programming work I've done in the past. If you'd like
to know more about it, feel free to ask in our correspondence.

# Contents

## Recoverable Virtual Memory (C on Linux)
  As part of my advanced operating systems course in my master's program, I
needed to implement recoverable virtual memory (rvm) to make a memory region
transaction-based and persistent across application crashes. This is my most
complex C project at around 1000 lines to date with much work in data
marshalling and self-created file formats.

  As a security note, this rvm library is susseptible to a file format attack
in which the attacker canges some of the offsets in the backing file for an
application. Abuse of the blind trust in the backing file would allow an
attacker to overwrite mapped-in regions of the target. The descision was taken
to leave in the vulnerability as all recoverable regions of the application
which are in the backing store would presumably be readable as well.

Explanation of the topic:
https://cs.nyu.edu/rgrimm/teaching/sp08-os/rvm.pdf
