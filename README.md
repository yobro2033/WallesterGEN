# Wallester Card Gen
**Last Review 02/02/2023** </br> 
An un-official API to generate cards on [Wallester](https://wallester.com/)
# Dependencies
Please install all requirements listed in requirements.txt
# Configure
**apiKey** - This should be given when you promt to create api key on the account. As far as I remembered, you will also be asked to create a pair of public and private key. Further informations how to generate pair RSA keys can be found [here](https://docs.oracle.com/en/cloud/cloud-at-customer/occ-get-started/generate-ssh-key-pair.html).</br>
**publicKey** - You should be able to see public key when using web-inspector to see details of any cards on your dashboard.</br>
**accountId** - You can see accountId when you tried to create a card. It should be a string in uuid4 format.</br>
**phone** - Make sure to have prefix before, no space or any other special characters.</br>
**password** - Could be anything.</br>
**firstName** - Could be anything.</br>
# How to use
Run wallestergen.py, the script will then ask you how many cards you wish to create. Bear in mind create over the limit of your account may result in additional charges. After that it will start to generate and write down card details in card.txt.
