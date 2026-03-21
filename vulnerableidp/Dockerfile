FROM ubuntu:xenial

#ENV http_proxy=''
#ENV https_proxy=''
#ENV no_proxy='127.0.0.1'

RUN apt-get update -y && \
    apt-get install --fix-missing -y apache2 simplesamlphp && \
    a2enconf simplesamlphp && \
    touch /usr/share/simplesamlphp/modules/exampleauth/enable && \
    sed -ie "s/'enable.saml20-idp' => false/'enable.saml20-idp' => true/g" /etc/simplesamlphp/config.php

#Build the IDP login landing page
#RUN echo "<h1>Jelly Stone IDP</h1><center>" > /usr/share/simplesamlphp/templates/includes/header.php
#RUN echo "</center> > /usr/share/simplesamlphp/templates/includes/footer.php 

COPY authsources.php /etc/simplesamlphp/
COPY saml20-idp-hosted.php /etc/simplesamlphp/metadata/
COPY saml20-sp-remote.php /etc/simplesamlphp/metadata/
COPY yogi-idp.local.crt /etc/ssl/certs/
COPY yogi-idp.local.pem /etc/ssl/certs/
COPY loginuserpass.php /usr/share/simplesamlphp/modules/core/templates/
COPY welcome.png /usr/share/simplesamlphp/www/resources/
EXPOSE 80

# Start the web service
CMD ["apache2ctl", "-D", "FOREGROUND"]
