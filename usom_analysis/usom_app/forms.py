from django import forms
from django.core.exceptions import ValidationError

class DomainIPForm(forms.Form):
    domain = forms.CharField(label='Domain', max_length=100, required=False)
    ip = forms.CharField(label='IP', max_length=15, required=False)

    def clean(self):
        cleaned_data = super().clean()
        domain = cleaned_data.get('domain')
        ip = cleaned_data.get('ip')

        if not domain and not ip:
            raise ValidationError("At least one of Domain or IP must be filled.")