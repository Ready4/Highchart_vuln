from django.db import models

# Create your models here.
class Vulnerability(models.Model):
    cve = models.CharField(max_length=200, blank=True)
    cvss = models.FloatField(null=True)
    cwe_name = models.CharField(max_length=200, blank=True)
    cwe_code = models.IntegerField()

    def __str__(self):
        return self.cve
