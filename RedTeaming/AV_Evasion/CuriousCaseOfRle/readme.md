♠# The curious case of the Run Length Encoder

## TL;DR

Run Length Encoding (RLE) is one of the simplest examples of data compression. Basically, RLE converts sequences of consecutive 
identical values into a pair n:v, where v is the value and n is the length of the sequence. The more similar values there 
are, the more values can be compressed.

It's easy to observe that the scheme can be really efficient in case of binary encoding "01", while it might be extremely
inefficient in cases when the alphabet used by the binary stream has a big cardinality.


