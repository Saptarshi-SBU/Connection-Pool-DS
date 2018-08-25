"""
 Unit Tests
 This module contains unit tests for conntable
"""
import os
import time
import random
import unittest
import subprocess
from time import sleep

TESTMODULE='conntable_ktest.ko'
OUTPUTDIR='/tmp/v1'
TESTTIME=15
BASE_THREADS=8
MAX_THREADS=12

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
	filename = '{}/proc-{}'.format(OUTPUTDIR, testid)
	cmd = 'echo {} > {}'.format(test_cmd, filename)
	RunCommand(cmd)
	cmd = 'cat /proc/fs/cacheobjs_test/conntable >> {}'. \
		format(filename)
	RunCommand(cmd)

    def runTest(self, test_id, nr_nodes, nr_conns, nr_insert_threads, \
                nr_lookup_threads, put_delay_us=0):
	cmd = 'insmod {} nr_nodes={} nr_conns={} nr_insert_threads={} '\
                'nr_lookup_threads={} put_delay_us={}'.format(TESTMODULE, \
                nr_nodes, nr_conns, nr_insert_threads, nr_lookup_threads, \
                put_delay_us)
        rc = RunCommand(cmd)
        self.assertEqual(rc, 0)
	sleep (TESTTIME)
	self.gatherStats(test_id, cmd)

    @unittest.skip('skip test')
    def test_001(self):
        """
            data structure unit for single thread lookup with one entry,
            does not test smp issues like cacheline bounces
        """
	self.runTest('test_001', nr_nodes=1, nr_conns=1, nr_insert_threads=1,
                        nr_lookup_threads=1)

    @unittest.skip('skip test')
    def test_002(self):
        """
            data structure unit for multi thread lookups with one entry,
            tests contended cases and smp issues like cacheline bounces
        """
	self.runTest('test_002', nr_nodes=1, nr_conns=1, nr_insert_threads=1,
                        nr_lookup_threads=BASE_THREADS)

    @unittest.skip('skip test')
    def test_003(self):
        """
            data structure unit for multi thread lookups with multiple entries,
            and 100us delay for testing resource busy conditions
        """
	self.runTest('test_003', nr_nodes=1, nr_conns=BASE_THREADS, nr_insert_threads=1,
                        nr_lookup_threads=BASE_THREADS, put_delay_us=100)

    @unittest.skip('skip test')
    def test_004(self):
        """
            data structure unit test for multiple threads insertion and lookups,
            full stress
        """
	self.runTest('test_004', nr_nodes=1, nr_conns=BASE_THREADS, nr_insert_threads=1,
                        nr_lookup_threads=BASE_THREADS, put_delay_us=1000)

    @unittest.skip('skip test')
    def test_005(self):
        """
            data structure unit test for multiple threads insertion and lookups,
            full stress with 100 us delay
        """
	self.runTest('test_005', nr_nodes=1, nr_conns=BASE_THREADS, nr_insert_threads=1,
                        nr_lookup_threads=MAX_THREADS)

    #@unittest.skip('skip test')
    def test_006(self):
        """
            data structure unit test for multiple threads insertion and lookups,
            full stress with 1ms delay (simulate dfc target io)
        """
	self.runTest('test_006', nr_nodes=1, nr_conns=BASE_THREADS, nr_insert_threads=1,
                        nr_lookup_threads=MAX_THREADS, put_delay_us=0)

    @unittest.skip('skip test')
    def test_007(self):
        """
            data structure unit test for multiple threads insertion and lookups,
            full stress with 1ms delay (simulate dfc target io)
        """
	self.runTest('test_007', nr_nodes=1, nr_conns=BASE_THREADS, nr_insert_threads=1,
                        nr_lookup_threads=MAX_THREADS, put_delay_us=1000)

    #@unittest.skip('skip test')
    def test_008(self):
        """
            data structure unit test for multiple threads insertion and lookups,
            full stress with 1ms delay (simulate dfc target io)
        """
	self.runTest('test_008', nr_nodes=1, nr_conns=BASE_THREADS, nr_insert_threads=1,
                        nr_lookup_threads=MAX_THREADS, put_delay_us=2000)

def TestDriver():
    suite = unittest.TestLoader().loadTestsFromTestCase(ConntableUnitTests)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == "__main__":
    TestDriver()
