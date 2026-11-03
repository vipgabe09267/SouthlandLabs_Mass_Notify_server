<?php
// Inert native lock protocol fixture: no FreePBX bootstrap, DB, or cron commands.
// Resource/key and release behavior follow Framework Cron getLock() and Symfony
// SemaphoreStore 6.2.12. The installed native classes are checked separately
// when available. This small fixture supports builds outside a PBX.
namespace Symfony\Component\Lock\Store { final class SemaphoreStore {} }
namespace Symfony\Component\Lock {
    final class LockFactory {
        public function __construct($store) {}
        public function createLock($resource,$ttl=60) {
            return new class($resource) {
                private $key; private $semaphore; private $held=false;
                public function __construct($resource) {$this->key=unpack('i',md5($resource,true))[1];}
                public function acquire($blocking=false) {
                    $this->semaphore=sem_get($this->key);
                    if($this->semaphore===false){throw new \RuntimeException('Fixture semaphore unavailable');}
                    return $this->held=sem_acquire($this->semaphore,!$blocking);
                }
                public function release() {
                    if($this->held){sem_remove($this->semaphore);$this->held=false;}
                }
                public function __destruct() {$this->release();}
            };
        }
    }
}
namespace FreePBX {
    final class Cron {
        private $user; private $lock;
        private function getLock() {
            if($this->lock){return $this->lock;}
            $factory=new \Symfony\Component\Lock\LockFactory(new \Symfony\Component\Lock\Store\SemaphoreStore());
            return $this->lock=$factory->createLock('crontab-'.$this->user,60);
        }
    }
}
