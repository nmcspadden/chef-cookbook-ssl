include_recipe "x509::default"

x509_certificate "munki2-#{node['fqdn']}" do
	certificate "/etc/ssl/munki2.sacredsf.org.crt"
	cacertificate "/etc/ssl/munki2_ca.crt"
	key "/etc/ssl/munki2.sacredsf.org.key" 
	ca "ChefCA" 
	cn node['fqdn']
	type "client" 
	bits 2048 
	days 365 
end
