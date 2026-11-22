#!/usr/bin/python3
"""Admission must reserve real entry headroom before extraction and journaling."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('inode_boundary_resource',ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_resource_capacity.py')
resource=importlib.util.module_from_spec(spec);spec.loader.exec_module(resource)
class InodeAdmissionBoundaries(unittest.TestCase):
    def test_standalone_installer_bootstrap_reserves_the_same_extraction_headroom(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        embedded=source.split("<<'SLS_RESOURCE_CAPACITY_PY'\n",1)[1].split('\nSLS_RESOURCE_CAPACITY_PY',1)[0]
        namespace={'__name__':'embedded_capacity_fixture','__file__':str(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_resource_capacity.py')}
        exec(compile(embedded,'embedded-resource-helper','exec'),namespace)
        storage=namespace['storage_requirements'](mode='prepare')
        self.assertFalse(self.admission(storage,'/tmp',5027)['resource_checks']['temporary']['ok'])
        self.assertTrue(self.admission(storage,'/tmp',5028)['resource_checks']['temporary']['ok'])
    def admission(self,storage,limited,free):
        budgets=storage['free_budgets_bytes'];inodes=storage['inode_budgets']
        other=[p for p in budgets if p!=limited]
        def filesystem(paths,available):
            return {'device':str(len(paths)),'paths':paths,'total_bytes':100*resource.GIB,
                'available_bytes':80*resource.GIB,'required_free_bytes':sum(budgets[p] for p in paths),
                'persistent':any(p not in ('/tmp','/var/tmp') for p in paths),'filesystem_type':'ext4',
                'available_inodes':available,'required_inodes':sum(inodes.get(p,0) for p in paths),
                'read_only':False,'inodes_exhausted':False,'volatile_targets':[]}
        machine={'effective_cpu_count':8,'effective_memory_bytes':16*resource.GIB,'storage':storage,
            'filesystems':[filesystem(other,1000000),filesystem([limited],free)]}
        return resource.evaluate(machine,25)
    def test_prepare_refuses_one_entry_below_supported_archive_and_bootstrap_headroom(self):
        # One5000-member extraction,12bootstrap helper files,16bounded
        # workspace/metadata entries before the measured install-phase check.
        storage=resource.storage_requirements(mode='prepare')
        self.assertFalse(self.admission(storage,'/tmp',5027)['resource_checks']['temporary']['ok'])
        self.assertTrue(self.admission(storage,'/tmp',5028)['resource_checks']['temporary']['ok'])
    def test_journal_reserves_two_supported_source_trees_without_inventing_a_third(self):
        storage=resource.storage_requirements(mode='install')
        # Candidate+legacy prior source5000each,12helpers,128metadata;
        # existing prior runtime snapshots are additionally measured elsewhere.
        self.assertFalse(self.admission(storage,resource.INSTALLER_JOURNAL,10139)['resource_checks']['storage']['ok'])
        self.assertTrue(self.admission(storage,resource.INSTALLER_JOURNAL,10140)['resource_checks']['storage']['ok'])
    def test_measured_candidate_entries_are_carried_into_journal_accounting(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            candidate=Path(name)/'candidate';candidate.mkdir(mode=0o755)
            (candidate/'one').write_bytes(b'one');(candidate/'two').write_bytes(b'two')
            for entry in candidate.iterdir():entry.chmod(0o644)
            payloads=resource.measure_release_payloads(candidate)
        storage=resource.storage_requirements(mode='install',payloads=payloads)
        # Three candidate entries (root plus two files),5000prior-source
        # entries,12helpers and128metadata. No third candidate source copy.
        self.assertFalse(self.admission(storage,resource.INSTALLER_JOURNAL,5142)['resource_checks']['storage']['ok'])
        self.assertTrue(self.admission(storage,resource.INSTALLER_JOURNAL,5143)['resource_checks']['storage']['ok'])
if __name__=='__main__':unittest.main()
