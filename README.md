# DoE-ProxyRack
This is the source code of DNS-over-Encryption client-side usability tests.
We run this code on CentOS 6 with Python 2.7.6.

For more details, you may refer to our paper: An End-to-End, Large-Scale Measurement of DNS-over-Encryption: How Far Hvae We Come? at [IMC '19](https://conferences.sigcomm.org/imc/2019/).

# The source files
### proxy_rack_single_threaded.py
This is the main program of the tests, containing all test items.

### dnsmsg, name and rdata.py
These individual files are imported by the main file. They are modified from the [dnspython](http://www.dnspython.org/) toolkit. 

Keep them and the main file in the same folder when running.

### The libraries
To measure the query time with reused connections, the Python libraries are inserted with timing functions. If you want to measure this, put the .pyc files in the package path of your Python environment (e.g., /usr/lib/python2.7/site-packages/dns/query.py), and set the lib_change flag as True in the main file.

This operation may affect your other Python programs using these libraries. Make sure to revert them when you are done!
