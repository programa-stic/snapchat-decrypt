# Decrypting Android Snapchat images

Python script for decrypting stored images from Snapchat version 5.0.34.nn
 **The script needs a rooted device and USB debugging turned on**.

**Remember to close the application before running the script**.

##News:
Support for Snapchat last version 5.0.38.1. Now checks wich version it's installed to obtain the images.

##How Snapchat decrypted images in previous versions

The new version of Snapchat (v5.0.34.nn), released on September 23rd, 2014) saves the received images differently than previous versions.
 Snapchat version 5.0.32.3 saved all encrypted images using the _AES_ cipher in _ECB_ mode with a hardcoded password ('_M02cnQ51Ji97vwT4_') under _/data/data/com.snapchat.android/cache/received\_image\_snaps_ folder. Scripts such as [1] could decrypt successfully images pulled from the device. Other ways to obtain the images include the use of the Xposed Framework and KeepChat [2].

##How Snapchat decrypts images now (as of October 10th, 2014)

The new Snapchat version encrypts images using the _AES_ algorithm in _CBC_ mode. For each received image a new random key and initialization vector (IV) is generated to encrypt it.  This results from the use by the  _ReceivedSnaps_ class  of the default algorithm constructor in _com.snapchat.android.util.crypto.CBCEncryption_  as it does not pass it a specific key and IV to use. When the app is stopped, the keys are saved in an encrypted file named _/data/data/com.snapchat.android/cache/bananas_ in order to be able to perform the decryption next time the app runs. Therefore it is necessary to stop the application before trying to decrypt the '_bananas_' file  to obtain all the keys to decrypt the images (_snaps_) . This file is encrypted using the _AES_ algorithm in _ECB_ mode but the key is predictable since the method that generates it can be found in the class _com.snapchat.android.util.crypto.SlightySecurePreferences_. The key is generated from a _MD5_ hash using the _Android ID_ concatenated with the string '_seems legit..._'.
The content of the decrypted file is a JSON structure. Under the _snapKeysAndIvs_  field one can find all the keys (the corresponding IVs are also unnecessarily stored) to decrypt the images. Each image key and IV has a _snapID_. This ID is associated to the corresponding image file in the _tcspahn.db_ database file under the table _snapimagesfiles_.

##Proof of concept code to decrypt Snapchat v 5.0.34.nn images

The python script first  stops the Snapchat application to force the storage of decryption keys in the _bananas_ file, it then pulls the images from Snapchat internal storage along with the _bananas_ cache file.  Next  it decrypts the last file with the predictable key to obtain the keys and IVs to decrypt the images. After that, it tries to decrypt each image with all possible pairs of key and IVs to find a successful decryption (this could be also done by pulling the database file and reading the _snapID_ associations table mentioned earlier).

If the script fails, try opening Snapchat again to make sure the snaps where downloaded and run the script again.

###Snapchat 5.0.38 update:
Snapchat updated the application after the script was released. No much has changed. The file 'bananas' was renamed to 'bananas1' and the way the index are saved inside changed since version 5.0.34.nn. 

##References

[1] https://gist.github.com/jamescmartinez/6913761

[2] http://repo.xposed.info/module/com.ramis.keepchat



