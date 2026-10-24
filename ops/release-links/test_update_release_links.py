import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('links',Path(__file__).with_name('update_release_links.py'))
links=importlib.util.module_from_spec(spec);spec.loader.exec_module(links)
class LinkTests(unittest.TestCase):
    def value(self):return {'version':'v0.3.0-rc15','source_revision':'a'*40,'assets':[{'name':name,'size':5,'sha256':'b'*64} for name in ('client.zip','client-source.zip','BUILD.json','SHA256SUMS.txt')]}
    def test_adds_both_links_idempotently_and_preserves_author_notes(self):
        value=self.value();body=links.render('Author notes',value)
        self.assertEqual(links.render(body,value),body)
        self.assertTrue(body.startswith('Author notes\n'))
        self.assertIn(links.BASE+'v0.3.0-rc15/client.zip',body)
        self.assertIn('https://github.com/'+links.REPO+'/releases/download/v0.3.0-rc15/client.zip',body)
        with self.assertRaises(ValueError):links.render(links.START,value)
    def test_rejects_wrong_release_source_or_asset_digest(self):
        value=self.value();release={'draft':False,'target_commitish':'a'*40,'tag_name':value['version'],'assets':[dict(item,digest='sha256:'+item['sha256']) for item in value['assets']]}
        links.verify_release(release,value)
        release['target_commitish']='c'*40
        with self.assertRaises(ValueError):links.verify_release(release,value)
        release['target_commitish']='a'*40;release['assets'][0]['digest']='sha256:'+'c'*64
        with self.assertRaises(ValueError):links.verify_release(release,value)
if __name__=='__main__':unittest.main()
