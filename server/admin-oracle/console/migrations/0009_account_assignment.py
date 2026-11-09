from django.db import migrations, models
import django.utils.timezone


def backfill(apps, schema_editor):
    Account=apps.get_model('console','ClientAccount');Audit=apps.get_model('console','Audit')
    for account in Account.objects.all().iterator():
        first=Audit.objects.filter(action='account.saved',resource=str(account.user_id)).order_by('occurred_at').first()
        account.assigned_at=first.occurred_at if first else account.updated_at
        account.assignment_basis='audit' if first else 'legacy_inferred'
        account.save(update_fields=['assigned_at','assignment_basis'])


class Migration(migrations.Migration):
    dependencies=[('console','0008_udpdiagnostic')]
    operations=[
        migrations.AddField('clientaccount','assigned_at',models.DateTimeField(null=True,editable=False)),
        migrations.AddField('clientaccount','assignment_basis',models.CharField(max_length=24,default='allocation',editable=False)),
        migrations.RunPython(backfill,migrations.RunPython.noop),
        migrations.AlterField('clientaccount','assigned_at',models.DateTimeField(default=django.utils.timezone.now,editable=False)),
    ]
