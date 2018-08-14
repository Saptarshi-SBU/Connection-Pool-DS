"""
 Unit Test
 This module contains unit tests for conntable
"""
import os
import time
import random
import unittest
import subprocess
from time import sleep

TESTMODULE='conntable_ktest.ko'
MAX_THREADS=8

def RunCommand(cmd, strict = True):
    ''' Executes a bash command '''

    print('Executing cmd :', cmd)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
    		stderr=subprocess.STDOUT, shell=True)
    out, err = process.communicate()
    if process.returncode is not 0:
        raise Exception("error executing " + cmd + ". " + out)
    else:
        return 0

class ConntableUnitTests(unittest.TestCase):

    def setUp(self):
        """
            Initialize
        """
	pass

    def tearDown(self):
        """
            TearDown
        """
	cmd = 'rmmod {}'.format(TESTMODULE)
        rc = RunCommand(cmd)
        self.assertEqual(rc, 0)

    def gatherStats(self, testid, test_cmd):
	filename = '/tmp/proc-{}'.format(testid)
	cmd = 'echo {} > {}'.format(test_cmd, filename)
	RunCommand(cmd)
	cmd = 'cat /proc/fs/cacheobjs_test/conntable >> {}'. \
		format(filename)
	RunCommand(cmd)

    def runTest(self, test_id, nr_nodes, nr_conns, nr_insert_threads, nr_lookup_threads, \
		put_delay_ms=0):
	cmd = 'insmod {} nr_nodes={} nr_conns={} nr_insert_threads={} nr_lookup_threads={} put_delay_ms={}'\
		.format(TESTMODULE, nr_nodes, nr_conns, nr_insert_threads, nr_lookup_threads, put_delay_ms)
        rc = RunCommand(cmd)
        self.assertEqual(rc, 0)
	sleep (5)
	self.gatherStats(test_id, cmd)

    #@unittest.skip('skip test')
    def test_001(self):
        """
            unit test with 1 lookup thread
        """
	self.runTest('test_001', nr_nodes=4, nr_conns=4, nr_insert_threads=1, \
                        nr_lookup_threads=1)

    #@unittest.skip('skip test')
    def test_002(self):
        """
            unit test with N/4 lookup threads
        """
	self.runTest('test_002', nr_nodes=4, nr_conns=4, nr_insert_threads=2, \
                        nr_lookup_threads=min(1, MAX_THREADS/4))

    #@unittest.skip('skip test')
    def test_003(self):
        """
            unit test with N/2 lookup threads
        """
	self.runTest('test_003', nr_nodes=4, nr_conns=4, nr_insert_threads=2, \
                        nr_lookup_threads=min(1, MAX_THREADS/2))

    #@unittest.skip('skip test')
    def test_004(self):
        """
            unit test with N lookup threads with no delay
        """
	self.runTest('test_004', nr_nodes=4, nr_conns=4, nr_insert_threads=2, \
                        nr_lookup_threads=MAX_THREADS)

    #@unittest.skip('skip test')
    def test_005(self):
        """
            unit test with N lookup threads with delay
        """
	self.runTest('test_005', nr_nodes=4, nr_conns=4, nr_insert_threads=2, \
                        nr_lookup_threads=MAX_THREADS, put_delay_ms=10)

def TestDriver():
    suite = unittest.TestLoader().loadTestsFromTestCase(ConntableUnitTests)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == "__main__":
    TestDriver()
