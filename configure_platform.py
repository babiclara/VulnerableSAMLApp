import json
import os
import subprocess
from shutil import copyfile


def sp_settings(json_file, sp_ip, idp_ip):
    json_file_handle = open(json_file, 'r')
    data = json.load(json_file_handle)
    json_file_handle.close()

    data['sp']['entityId'] = f'http://{sp_ip}:8000/metadata/'
    data['sp']['assertionConsumerService']['url'] = f'http://{sp_ip}:8000/?acs'
    data['sp']['singleLogoutService']['url'] = f'http://{sp_ip}:8000/?sls'

    data['idp']['entityId'] = f'http://{idp_ip}/simplesamlphp/saml2/idp/metadata.php'
    data['idp']['singleSignOnService']['url'] = f'http://{idp_ip}/simplesamlphp/saml2/idp/SSOService.php'
    data['idp']['singleLogoutService']['url'] = f'http://{idp_ip}/simplesamlphp/saml2/idp/SingleLogoutService.php'

    json_file_handle  = open(json_file, 'w+')
    json_file_handle.write(json.dumps(data, indent=4))
    json_file_handle.close()


def idp_settings(settings_file, sp_ip):
    original_text = '127.0.0.1:8000'
    new_text = f'{sp_ip}:8000'

    original_text_blob = open(settings_file).read()
    open(settings_file, 'w').write(original_text_blob.replace(original_text, new_text))


def build_docker(image_build):
    # Builds and runs the docker image defined for the host. 
    SP_IMAGE = 'sp:1.0'
    if image_build == 'idp':
        build = subprocess.Popen(['docker', 'build', '-t', 'idp:1.0', 'vulnerableidp/'])
        build.wait()
        run = subprocess.Popen(['docker', 'run', '-it', '--rm', '--name', 'sp', '-d', '-p', '80:80', SP_IMAGE])
        run.wait()
        check = subprocess.Popen(['docker', 'ps', '--filter', '--name', 'sp'])
        check.wait()
        print('\n All done run the IDP should be running now.')
        print('To run the image manually after shutting it down use the command below:')
        print(f'\t sudo docker run -it --rm --name {image_build} -d -p 80:80 {image_build}:1.0')
    else:
        build = subprocess.Popen(['docker', 'build', '-t', SP_IMAGE, 'vulnerablesp/'])
        build.wait()
        run = subprocess.Popen(['docker', 'run', '-it', '--rm', '--name', 'sp', '-d', '-p', '8000:8000', SP_IMAGE])
        run.wait()
        check = subprocess.Popen(['docker', 'ps', '--filter', '--name', 'sp'])
        check.wait()
        print('\n All done the SP image should be running.')
        print('To run the image manually after shutting it down use the command below:')
        print(f'\t sudo docker run -it --rm --name {image_build} -d -p 8000:8000 {image_build}:1.0')

def get_host_config_option():
    while True:
        try:
            option = int(input('#  '))
            if option in (1, 2):
                return option
            print('Please enter 1 or 2')
        except Exception:
            print('Must be a number')


def get_docker_direction():
    while True:
        try:
            direction = input('Do you want to also create and run the Docker image for this host, Y/N? ')
            if direction[0].lower() in ('y', 'n'):
                return direction
            print('Must be either a Y or N')
        except Exception as e:
            print(f'Must be a Y or N: {e}')

def main():
    # Reset the config files for each run to give people the ability to re-run this if they typo something
    # saves them from having to re-clone repo or edit the files manually

    copyfile('vulnerablesp/yogiSP/saml/settings.original','vulnerablesp/yogiSP/saml/settings.json')
    copyfile('vulnerableidp/saml20-sp-remote.original','vulnerableidp/saml20-sp-remote.php')

    print(" Begining the configuration process. \n")

    print('---------------------------------------------')
    print(" Please note that this script is basically doing a find in replace on specific strings that exist in the initial files cloned from the repository.\n If you've already ran this script once and specified different IPs/hostnames for the SP and IDP, there is a strong chance it will not actually update the configuration files for you.\n You should consider manually editing the configuration files or deleteing and re-cloning the repository.")
    print('---------------------------------------------')

    print('\n Which server are we configuring? \n 1 - Identity Prodiver (IDP) \n 2 - Serivce Provider/Web App (SP)')

    host_config_option = get_host_config_option()
    docker_direction = get_docker_direction()

    if docker_direction == 'Y' and os.geteuid() != 0:
        sys.exit('Please re-run this script with root privileges if you want to have it build the docker commands for you')

    sp_ip = input('What is the hostname/IP for the SP? ')
    idp_ip = input('What is the hostname/IP for the IDP? ')

    # Configure the Identity Platform (IDP)
    if host_config_option is 1:
        settings_file = 'vulnerableidp/saml20-sp-remote.php'
        idp_settings(settings_file, sp_ip)
        build_docker('idp')

    # Configure the web application / Service Provider (SP)
    elif host_config_option is 2:
        json_file = 'vulnerablesp/yogiSP/saml/settings.json'
        sp_settings(json_file, sp_ip, idp_ip)
        build_docker('sp')

if __name__ == "__main__":
    main()
