from django.core.management.base import BaseCommand
from console import control
from console.models import ClientAccount

class Command(BaseCommand):
    help='Synchronize immutable credential-allocation dates to the restricted root ledger'
    def handle(self,**options):
        snapshot=control.call('state','system:health',{})
        ids={u['id']:u for u in snapshot['users']}
        for account in ClientAccount.objects.all().iterator():
            user=ids.get(str(account.user_id))
            if not user:continue
            expected='account:'+account.assignment_basis
            if user.get('cycle',{}).get('assignment_basis')==expected:continue
            control.call('user.anchor','system:account-sync',{'user_id':str(account.user_id),'assigned_at':int(account.assigned_at.timestamp()),'basis':account.assignment_basis})
        self.stdout.write('ACCOUNT_CYCLES=SYNCED')
