#!/usr/bin/python3
"""Download workers must not inherit leases or survive their owning helper."""
import fcntl
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import select
import signal
import socket
import time
import unittest
from unittest.mock import patch
import urllib.request

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise RuntimeError('Run only through tools/run_isolated_tests.sh')
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('v020_lifetime_http_fixture',ROOT/'tools/test_installer_download_deadline_v020.py')
HTTP=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(HTTP)


class DownloadWorkerLifetime(unittest.TestCase):
    def setUp(self):
        self.fixture=HTTP.DownloadDeadline(methodName='runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.upgrade=HTTP.UPGRADE
        self.root=self.fixture.destination.parent

    def transport(self,path,observed=None,descriptors=()):
        opener=self.fixture.real_opener;port=self.fixture.server.server_port
        class LocalTransport:
            def open(self,request,timeout):
                if observed is not None:
                    inherited=[]
                    for descriptor,expected in descriptors:
                        try:
                            info=os.fstat(descriptor)
                            inherited.append((info.st_dev,info.st_ino,info.st_mode)==expected)
                        except OSError:inherited.append(False)
                    temporary=observed.with_name(observed.name+'.pending')
                    temporary.write_text(json.dumps({'pid':os.getpid(),'inherited':inherited}))
                    os.replace(temporary,observed)
                return opener.open(urllib.request.Request('http://127.0.0.1:'+str(port)+path,
                    headers=dict(request.header_items())),timeout=timeout)
        return LocalTransport()

    def test_worker_drops_inherited_regular_directory_and_socket_descriptors(self):
        lock=self.root/'coordinator.lock';lock.write_bytes(b'')
        descriptor=os.open(lock,os.O_RDWR);directory=os.open(self.root,os.O_DIRECTORY|os.O_RDONLY)
        endpoint=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            descriptors=[]
            for item in (descriptor,directory,endpoint.fileno()):
                info=os.fstat(item);descriptors.append((item,(info.st_dev,info.st_ino,info.st_mode)))
            observation=self.root/'worker-fds.json'
            with patch.object(self.upgrade,'DOWNLOAD_DEADLINE_SECONDS',2),\
                 patch.object(self.upgrade.urllib.request,'build_opener',return_value=self.transport('/fast',observation,descriptors)):
                self.upgrade.download(HTTP.URL,self.fixture.destination,64)
            self.assertEqual(json.loads(observation.read_text())['inherited'],[False,False,False],
                             'Network worker retained root coordinator or unrelated native descriptors')
            for item,identity in descriptors:
                info=os.fstat(item);self.assertEqual((info.st_dev,info.st_ino,info.st_mode),identity)
            self.assertEqual(self.fixture.destination.read_bytes(),b'complete fixture bytes')
        finally:
            endpoint.close();os.close(directory);os.close(descriptor)

    def test_parent_death_kills_only_its_network_worker_and_releases_real_fence(self):
        lock=self.root/'parent-fence.lock';lock.write_bytes(b'')
        observation=self.root/'worker-pid.json'
        transport=self.transport('/slow',observation)
        def owning_helper():
            descriptor=os.open(lock,os.O_RDWR)
            try:
                fcntl.flock(descriptor,fcntl.LOCK_EX)
                with patch.object(self.upgrade,'DOWNLOAD_DEADLINE_SECONDS',20),\
                     patch.object(self.upgrade.urllib.request,'build_opener',return_value=transport):
                    self.upgrade.download(HTTP.URL,self.fixture.destination,1024)
            finally:os.close(descriptor)
        helper=multiprocessing.get_context('fork').Process(target=owning_helper)
        helper.start();worker_pidfd=None;probe=None
        try:
            deadline=time.monotonic()+2
            while not observation.exists() and time.monotonic()<deadline:time.sleep(0.01)
            self.assertTrue(observation.exists(),'Own worker did not reach the actual private HTTP transport')
            worker=json.loads(observation.read_text())['pid'];worker_pidfd=os.pidfd_open(worker)
            probe=os.open(lock,os.O_RDWR)
            with self.assertRaises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            helper.kill();helper.join(timeout=2);self.assertEqual(helper.exitcode,-signal.SIGKILL)
            deadline=time.monotonic()+0.5;acquired=False
            while time.monotonic()<deadline:
                try:fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB);acquired=True;break
                except BlockingIOError:time.sleep(0.01)
            self.assertTrue(acquired,'Dead parent left its coordinator fence held by the network child')
            self.assertTrue(select.select([worker_pidfd],[],[],0.5)[0],
                            'Network worker outlived its owning helper')
        finally:
            if helper.is_alive():helper.kill();helper.join(timeout=2)
            if worker_pidfd is not None:
                try:signal.pidfd_send_signal(worker_pidfd,signal.SIGKILL)
                except ProcessLookupError:pass
                os.close(worker_pidfd)
            if probe is not None:os.close(probe)
            if not helper.is_alive():helper.close()


if __name__=='__main__':unittest.main()
