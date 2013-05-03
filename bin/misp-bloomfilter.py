#!/usr/bin/python
#
# Creating a bloomfilter from records in a MISP XML export.
# The created bloomfilter database can be then used to query logs files
# without having to share the MISP database where the analysis
# is performed.
#
# Be aware that you can check against a bloomfilter any finite
# set of data. Especially IP addresses (2^32) can be easily enumerate
# from a bloomfilter.
#
# This software is free software released the AGPL.
#
# Copyright (C) 2012-2013 Alexandre Dulaunoy (a@foo.be)


from optparse import OptionParser
import sys
import pybloomfilter

usage = "usage: %s url(s)" % sys.argv[0]
parser = OptionParser(usage)

# find the right lxml/elementtree library
try:
  from lxml import etree
except ImportError:
  try:
    # Python 2.5
    import xml.etree.cElementTree as etree
  except ImportError:
    try:
      # Python 2.5
      import xml.etree.ElementTree as etree
    except ImportError:
      try:
        # normal cElementTree install
        import cElementTree as etree
      except ImportError:
        try:
          # normal ElementTree install
          import elementtree.ElementTree as etree
        except ImportError:
          print("Failed to import ElementTree from any known place")


def log(message=None, type="debug"):
    if message:
        if type == "debug":
             sys.stderr.write(message+"\n")
        return True
    return None


parser.add_option("-t", "--type", dest="recordtype", help="type of the record (default record is 'domain')", default="domain")
parser.add_option("-f", "--file", dest="filename", help="filename of the MISP XML file to read (default MISP XML dump is 'misp.xml')", default="misp.xml")
parser.add_option("-l", "--lookup", dest="lookup", help="lookup a value in a bloomfilter", default=False)
parser.add_option("-s", "--streamlookup", dest="streamlookup", help="lookup a set of value from stdin in a bloomfilter", default=False, action='store_true')
parser.add_option("-d", "--dbdir", dest="dbdir", help="Bloomfilters directory (default is '.')", default=".")

(options, args) = parser.parse_args()

bloomfile = options.dbdir+"/"+options.recordtype+".bloom"

if options.lookup:
    bloomfilter = pybloomfilter.BloomFilter.open(bloomfile)
    if options.lookup in bloomfilter:
        log(message=options.lookup+" True")
    else:
        log(message=options.lookup+" False")
    exit()

elif options.streamlookup:
    bloomfilter = pybloomfilter.BloomFilter.open(bloomfile)
    for lookup in sys.stdin:
        lookup = lookup.rstrip()
        if lookup in bloomfilter:
            log(message=lookup+" True")
        else:
            log(message=lookup+" False")
    exit()
else:
    # bloomfilter setup - size/probability should be based on the number of records
    # found (TODO)
    bloomfilter = pybloomfilter.BloomFilter(10000, 0.01, bloomfile)

tree = etree.parse(options.filename)

typematch = False
for element in tree.iter():
   if element.tag == "type" and element.text == options.recordtype:
        typematch = True
   if typematch and element.tag == "value1":
        bloomfilter.add(element.text)
        if element.text in bloomfilter:
            log(message=element.text+" added")
        typematch = False

bloomfilter.sync()
