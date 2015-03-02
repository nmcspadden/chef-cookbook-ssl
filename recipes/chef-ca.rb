include_recipe "x509::default"

x509_certificate "munki2.sacredsf.org" do
	certificate "/etc/ssl/munki2.sacredsf.org.crt"
	cacertificate "/etc/ssl/munki2_ca.crt"
	key "/etc/ssl/munki2.sacredsf.org.key" 
	ca "ChefCA" 
	type "server" 
	bits 2048 
	days 365 
end
