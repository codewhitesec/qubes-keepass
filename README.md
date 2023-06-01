### Qubes Keepass

----

*qubes-keepass* is a [rofi](https://github.com/davatorium/rofi) based frontend for [KeePassXC](https://keepassxc.org/)
which integrates nicely with the isolation and security features of [Qubes OS](https://www.qubes-os.org/). It enables you
to easily copy credentials to the currently focused Qube, to define allow lists for credentials based on Qube names and to
automatically clear the Qubes clipboard after a configurable amount of time.

![qubes-keepass-example](https://github.com/codewhitesec/qubes-keepass/assets/49147108/9512901f-93f7-4bc4-bd20-951a45000171)


*qubes-keepass* is inspired by [rofi-pass](https://github.com/carnager/rofi-pass) which provides a rofi based frontend
for the password manager [pass](https://www.passwordstore.org/).


### Installation

----

*qubes-keepass* relies on *Qubes qrexec* mechanism and requires multiple installation steps in different Qubes. In the
following, it is assumed that your *KeePassXC* database is contained within a Qube named `vault`, that your window manager
is [i3](https://www.qubes-os.org/doc/i3/) and that you have an *AppVM Qube* called `app-vm`. In addition, make sure that
*rofi* is installed in `vault` and *xclip* is installed in `app-vm`.


#### dom0

In `dom0` create a policy file for the `custom.QubesKeepass` *qrexec* service. This service will be invoked by your `vault`
Qube to copy credentials to other *AppVMs*:

```console
[user@dom0 ~]$ cat /etc/qubes-rpc/policy/custom.QubesKeepass
vault $anyvm allow notify=true
```

According to your preferences, you could also choose `ask` instead of the `allow` action or remove the `notify=true` option,
if you do not want to be notified when something gets copied via *qubes-keepass*.

If you're using Qubes 4.1 and want to follow the new *qrexec* policy system:

```console
[user@dom0 ~]$ cat /etc/qubes/policy.d/30-user.policy
...
custom.QubesKeepass * vault @anyvm allow notify=yes
```

Now copy the [qubes-keepass-dom0.sh](./qubes-keepass-dom0.sh) script to a location within your `$PATH` environment variable
and make sure that it is executable.

Finally, set up a shortcut for invoking `qubes-keepass-dom0.sh` in your *i3* configuration file and make sure that
the window class `Rofi` is configured to floating:

```console
[user@dom0 ~]$ cat /.config/i3/config
...
bindsym $mod+p exec --no-startup-id qubes-keepass-dom0.sh
for_window [class="Rofi"] floating enable
```


#### vault

In your `vault` VM you need to enable the *Secret Service* integration for *KeePassXC*. This can be configured within
the database settings and requires that no other *Secret Service Providers* is running. By default, you probably have
`gnome-keyring-daemon` as *Secret Service Provider* running in your `vault` VM. The recommended way to disable it is
by modifying it's autostart entry. First, setup a [binddir](https://www.qubes-os.org/doc/bind-dirs/) for your `vault` VM:

```console
[user@vault ~]$ cat /rw/config/qubes-bind-dirs.d/50_user.conf
binds+=( '/etc/xdg/autostart/gnome-keyring-secrets.desktop' )
```

Now restart the `vault` VM and add `Hidden=true` to the `/etc/xdg/autostart/gnome-keyring-secrets.desktop` file and comment
the line containing the `Exec` statement. According to the [documentation](https://specifications.freedesktop.org/autostart-spec/autostart-spec-latest.html)
creating a file `~/.config/autostart/gnome-keyring-secrets.desktop` with contents `Hidden=true` would also be sufficient, but
this did not work during our tests.

```console
[user@vault ~]$ cat /etc/xdg/autostart/gnome-keyring-secrets.desktop
...
#Exec=/usr/bin/gnome-keyring-daemon --start --components=secrets
Hidden=true
```

After restarting the `vault` VM again, the `gnome-keyring-daemon` should no longer start up and you can enable the *Secret
Service* integration in the *KeePassXC* Tools settings.

Additionally, you need to expose the credentials you want to use with *qubes-keepass* to the *Secret Service* within the
database specific security settings. If you simply want to use your entire database with *qubes-keepass*, allow access
to the *Root* folder of your database.

Finally, copy the [qubes-keepass.py](./qubes-keepass.py) script to your `vault` VM and make sure it is executable. Also make
sure that the location specified in [qubes-keepass-dom0.sh](./qubes-keepass-dom0.sh) matches the location you copied the script
to (default is `/home/user/.local/bin/qubes-keepass.py`). Also the configuration file [qubes-keepass.ini](./qubes-keepass.ini)
needs to be copied to your `vault` VM. A good location for this one is `/home/user/.config/qubes-keepass.ini`.


#### app-vm

For each *AppVM* that is allowed to obtain credentials from *qubes-keepass*, you need to setup an *qrexec* service. This service
is essentially just a pipe to `xclip` and looks like this:

```console
[user@app-vm ~]$ cat /etc/qubes-rpc/custom.QubesKeepass
#!/usr/bin/sh

xclip -selection clipboard
```

Make sure that it is executable and that such a file exists on each *AppVM* you want to use *qubes-keepass* with. As the *qrexec*
service is defined outside the persistent portions of an *AppVM*, you probably want to set it up within the *AppVMs* template.


### Usage

----

After pressing the configured shortcut for `qubes-keepass-dom0.sh`, *qubes-keepass* determines your currently focused Qube
and displays available credentials from your *KeePassXC* database in *rofi*. After you selected a credential, it is copied
to previously determined focused Qube using the `custom.QubesKeepass` *qrexec* service.

Within *rofi* you can press the following keys to copy different attributes of the credential:

* `Return` or `Ctrl+c`: Copy password
* `Ctrl+b`: Copy username
* `Ctrl+Shift+u`: Copy URL

All of those can be configured using the *qubes-keepass* [configuration-file](/qubes-keepass.ini).


### Configuration

----

*qubes-keepass* accepts configuration options from two different places. Global options that affect the behavior of *qubes-keepass*
itself can be specified within the `qubes-keepass.ini` configuration file. During startup, such a configuration file is searched in
the following locations:

* ~/.config/qubes-keepass.ini
* ~/.config/qubes-keepass/config.ini
* ~/.config/qubes-keepass/qubes-keepass.ini
* /etc/qubes-keepass.ini
* /etc/qubes-keepass/config.ini
* /etc/qubes-keepass/qubes-keepass.ini

Moreover, *qubes-keepass* also supports some credential specific configurations, that can be applied within the *Notes* section
of a *KeePassXC* credential. The following listing shows an example for such a configuration:

```ini
[QubesKeepass]
qubes = work, personal
timeout = 5
trust = 4
```

#### Credential Specific Options

* `timeout` - specifies a credential specific timeout before the clipboard gets cleared after the credential was copied
* `qubes` - specifies an allow list of qubes for the credential. The credential can only be copied into the specified qubes
* `trust` - specifies the minimum trust level that a qube needs to be able to receive this credential
* `meta` - specifies a list of qubes that are only allowed to obtain meta information of the credential (username, url)
* `icon` - specifies the icon for the credential. Can be a default icon name (e.g. `firefox`) or a file system path. To display
  icons within *rofi*, you also need to add the `-show-icons` *rofi-option* in your `qubes-keepass.ini` file


#### Global Options

* `regex` - treat specified qube names like regular expressions. This also applies to credential specific options
* `timeout` - default timeout the clipboard gets cleared after a credential was copied
* `smart_sort` - sort credentials by their usage count. A credential accessed within the last 30 seconds is always displayed first
* `restricted` - qubes listed in this configuration can only obtain credentials that are explicitly configured for them
* `unrestricted` - when this configuration is not empty, all other qubes are treated as restricted
* `minimum_trust` - only qubes with a trust level above the specified value are able to obtain credentials via *qubes-keepass*

When using the `minimum_trust` option, *qubes-keepass* uses the default numerical values of the Qubes OS trust levels:

| Label  | Trust Level |
| ------ | ----------- |
| red    | 1           |
| orange | 2           |
| yellow | 3           |
| green  | 4           |
| gray   | 5           |
| blue   | 6           |
| purple | 7           |
| black  | 8           |

When using your own ordering (e.g. treating `red` as fully trusted), you can assign different trust levels within the
`qubes-keepass.ini` file.

#### Theme

If you want to setup the custom theme displayed within this README file, just copy the [qubes-keepass.rasi](/theme/qubes-keepass.rasi) theme
and the associated [background image](/theme/background.png) to your `~/.config/rofi` folder and add `-theme qubes-keepass` to the `rofi.options`
section in your `qubes-keepass.ini`


### FAQ

----

**Q**: Isn't exposing credentials via DBus insecure?\
**A**: No. Despite Keepass attempts to protect your credentials in memory, you should assume that each process running on the same machine
as your Keepass instance is able to access these credentials by dumping them from memory. DBus access makes the process of dumping credentials
more comfortable, but it is not a requirement. Moreover, your `vault` VM is considered trusted and other VMs are not able to access your secrets.
If you are really concerned about the DBus access, you can configure Keepass to display a prompt for each credential access via DBus.

**Q**: Should I configure `custom.QubesKeepass` using the `ask` or `allow` policy?\
**A**: It depends. `custom.QubesKeepass` adds a communication channel from your `vault` VM to other VMs. This communication channel is only unidirectional,
but it could still allow to exfiltrate data from your `vault` into an *online* VM. That being said, the same is true for other Qubes mechanisms like
[split-SSH](https://github.com/Qubes-Community/Contents/blob/master/docs/configuration/split-ssh.md). If having a malicious process in your `vault` VM that
exfiltrates data using your clipboard is something you worry about, you should use `ask`. If you like things more comfortable, you should use `allow` instead.
