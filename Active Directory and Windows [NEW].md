# Active Directory (AD) and Windows

## Checklist
- [ ] Password Searching
  - [ ] LaZagne
  - [ ] Snaffler
  - [ ] mimikittenz
- [ ] Password Reuse
- [ ] Bloodhound
- [ ] Kerberos
  - [ ] Kerbrute Enumeration
  - [ ] Pass the Ticket
  - [ ] Kerberoasting
  - [ ] AS-REP Roasting
  - [ ] Golden Ticket
  - [ ] Silver Ticket
  - [ ] Skeleton Key
- [ ] Pass the Hash

## Tools

- [kerbrute](https://github.com/ropnop/kerbrute) - to brute-force and enumerate valid active-directory users by abusing the Kerberos pre-authentication
- [Rubeus](https://github.com/GhostPack/Rubeus) - for Kerberos

## Commands

## Wordlists

- User and Password: https://github.com/Cryilllic/Active-Directory-Wordlists/tree/master

## Kerberos (Windows ticket-granting service (TGS))

Kerberos is a computer network authentication protocol that operates based on tickets, allowing nodes to securely prove their identity to one another over a non-secure network. It primarily aims at a client-server model and provides mutual authentication, where the user and the server verify each other's identity. The Kerberos protocol messages are protected against eavesdropping and replay attacks, and it builds on symmetric-key cryptography, requiring a trusted third party.

Kerberos is the default authentication service for Microsoft Windows domains. It is intended to be more "secure" than NTLM by using third party ticket authorization as well as stronger encryption.

#### Common Terminology:

- Ticket Granting Ticket (TGT) - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
- Key Distribution Center (KDC) - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
- Authentication Service (AS) - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
- Ticket Granting Service (TGS) - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
- Service Principal Name (SPN) - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
- KDC Long Term Secret Key (KDC LT Key) - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
- Client Long Term Secret Key (Client LT Key) - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
- Service Long Term Secret Key (Service LT Key) - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
- Session Key - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
- Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

#### AS-REQ w/ Pre-Authentication In Detail

The AS-REQ step in Kerberos authentication starts when a user requests a TGT from the KDC. In order to validate the user and create a TGT for the user, the KDC must follow these exact steps. The first step is for the user to encrypt a timestamp NT hash and send it to the AS. The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a TGT as well as a session key for the user.

#### Ticket Granting Ticket Contents

In order to understand how the service tickets get created and validated, we need to start with where the tickets come from; the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket.

![image](https://github.com/user-attachments/assets/4ff512b5-8170-40e5-94d4-efec0f507416)

#### Service Ticket Contents

To understand how Kerberos authentication works you first need to understand what these tickets contain and how they're validated. A service ticket contains two portions: the service provided portion and the user-provided portion. I'll break it down into what each portion contains.

- Service Portion: User Details, Session Key, Encrypts the ticket with the service account NTLM hash.
- User Portion: Validity Timestamp, Session Key, Encrypts with the TGT session key.

![image](https://github.com/user-attachments/assets/97633c72-33bd-40e7-a222-38c69dd3eacd)

#### Kerberos Authentication Overview

![image](https://github.com/user-attachments/assets/ac16e648-4198-466c-8c74-1f481035fadc)

1. AS-REQ - 1.) The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).
2. AS-REP - 2.) The Key Distribution Center verifies the client and sends back an encrypted TGT.
3. TGS-REQ - 3.) The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.
4. TGS-REP - 4.) The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.
5. AP-REQ - 5.) The client requests the service and sends the valid session key to prove the user has access.
6. AP-REP - 6.) The service grants access

#### Kerberos Tickets Overview

The main ticket you will receive is a ticket-granting ticket (TGT). These can come in various forms, such as a **`.kirbi`** for **Rubeus** and **`.ccache`** for **Impacket**. A ticket is typically base64 encoded and can be used for multiple attacks. 

The ticket-granting ticket is only used to get service tickets from the KDC. When requesting a TGT from the KDC, the user will authenticate with their credentials to the KDC and request a ticket. The server will validate the credentials, create a TGT and encrypt it using the krbtgt key. The encrypted TGT and a session key will be sent to the user.

When the user needs to request a service ticket, they will send the TGT and the session key to the KDC, along with the service principal name (SPN) of the service they wish to access. The KDC will validate the TGT and session key. If they are correct, the KDC will grant the user a service ticket, which can be used to authenticate to the corresponding service.

#### Attack Privilege Requirements

- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required

### Kerbrute

﻿Kerbrute is a popular enumeration tool used to brute-force and enumerate valid active-directory users by abusing the Kerberos pre-authentication.

#### Abusing Pre-Authentication Overview

By brute-forcing Kerberos pre-authentication, you do not trigger the account failed to log on event which can throw up red flags to blue teams. When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist.

#### Enumerating Users w/ Kerbrute

Enumerating users allows you to know which user accounts are on the target domain and which accounts could potentially be used to access the network.

> [Wordlist](https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt)

```
./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
```
- `--dc`: Domain Controller address
- `-d`: Domain Name

### Rubeus

Just some of the many tools and attacks include overpass the hash, ticket requests and renewals, ticket management, ticket extraction, harvesting, pass the ticket, AS-REP Roasting, and Kerberoasting.

#### Harvesting Tickets w/ Rubeus

Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

```
# to harvest for TGTs every 30 seconds
.\Rubeus.exe harvest /interval:30
```

#### Brute-Forcing / Password-Spraying w/ Rubeus

Rubeus can both brute force passwords as well as password spray user accounts.
- When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account.
- In password spraying, you give a single password such as Password1 and "spray" against all found user accounts in the domain to find which one may have that password.

This attack will take a given Kerberos-based password and spray it against all found users and give a `.kirbi` ticket. This ticket is a TGT that can be used in order to get service tickets from the KDC as well as to be used in attacks like the pass the ticket attack.

```
# a given password and "spray" it against all found users then give the .kirbi TGT for that user
.\Rubeus.exe brute /password:Password1 /noticket
```

> Be mindful of how you use this attack as it may lock you out of the network depending on the *account lockout policies*.

### Kerberoasting

### AS-REP Roasting with Rubeus and Impacket

### Golden/Silver Ticket Attacks

### Pass the Ticket (PtH)

### Skeleton key attacks using mimikatz
