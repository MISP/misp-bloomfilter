misp-bloomfilter
================

misp-bloomfilter is a tool creating a bloomfilter from records in a MISP XML export.
The created bloomfilter database can be then used to query logs files
without having to share the MISP database where the analysis
is performed. This can be used as an alternative way to lookup IOCs without
having to share these directly.

Requirements
------------

* Python
* pybloomfilter

Security Considerations
-----------------------

Be aware that you can check against a bloomfilter any finite
set of data. Especially IP addresses (2^32) can be easily enumerated
from a bloomfilter. If you are using bloomfilters to avoid sharing
the records from MISP, you should verify if the set cannot be easily
enumerated.

Usage
-----

        Usage: misp-bloomfilter.py url(s)

        Options:
          -h, --help            show this help message and exit
          -t RECORDTYPE, --type=RECORDTYPE
                                type of the record (default record is 'domain')
          -f FILENAME, --file=FILENAME
                                filename of the MISP XML file to read (default MISP
                                XML dump is 'misp.xml')
          -l LOOKUP, --lookup=LOOKUP
                                lookup a value in a bloomfilter
          -s, --streamlookup    lookup a set of value from stdin in a bloomfilter
          -d DBDIR, --dbdir=DBDIR
                                Bloomfilters directory (default is '.')
          -u URL, --url=URL     url to access MISP
          -a AUTHKEY, --authkey=AUTHKEY
                                authentication key to access MISP


Example
-------

Creating a bloomfilter database from the domain record type:

    python misp-bloomfilter.py -f ../in/misp.xml -d ../db/ -t domain

Creating a bloomfilter database from the ip-dst type using the REST MISP API:

    python misp-bloomfilter.py -u https://misp.server/ -a <your auth key> -d ../db/ -t ip-dst

Testing the database for the existence of a record:

    python misp-bloomfilter.py -f ../in/misp.xml -d ../db/ -t domain -l foo.bar
    foo.bar True


License
-------

This software is licensed under GNU Affero General Public License version 3.

Copyright (c) 2012, 2013 Alexandre Dulaunoy (a AT foo be)
