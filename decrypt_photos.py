# -*- coding: utf-8 -*-
## Copyright (c) 2014, Fundación Dr. Manuel Sadosky. Todos los derechos reservados.
##
## La redistribución y el uso en las formas de código fuente y binario, con o sin
## modificaciones, están permitidos siempre que se cumplan las siguientes condiciones:
##
## 1. Las redistribuciones del código fuente deben conservar el aviso de copyright
##   anterior, esta lista de condiciones y el siguiente descargo de responsabilidad.
##
## 2. Las redistribuciones en formato binario deben reproducir el aviso de copyright
##  anterior, esta lista de condiciones y la siguiente renuncia en la documentación
##   y/u otros materiales suministrados con la distribución.
##
## ESTE SOFTWARE SE SUMINISTRA POR LA Fundación Dr. Manuel Sadosky ''COMO ESTÁ'' Y CUALQUIER
## GARANTÍA EXPRESA O IMPLÍCITAS, INCLUYENDO, PERO NO LIMITADO A, LAS GARANTÍAS
## IMPLÍCITAS DE COMERCIALIZACIÓN Y APTITUD PARA UN PROPÓSITO DETERMINADO SON
## RECHAZADAS. EN NINGÚN CASO Fundación Dr. Manuel Sadosky SERÁ RESPONSABLE POR NINGÚN
## DAÑO DIRECTO, INDIRECTO, INCIDENTAL, ESPECIAL, EJEMPLAR O CONSECUENTE (INCLUYENDO,
## PERO NO LIMITADO A, LA ADQUISICIÓN DE BIENES O SERVICIOS; LA PÉRDIDA DE USO, DE
## DATOS O DE BENEFICIOS; O INTERRUPCIÓN DE LA ACTIVIDAD EMPRESARIAL) O POR
## CUALQUIER TEORÍA DE RESPONSABILIDAD, YA SEA POR CONTRATO, RESPONSABILIDAD ESTRICTA
## O AGRAVIO (INCLUYENDO NEGLIGENCIA O CUALQUIER OTRA CAUSA) QUE SURJA DE CUALQUIER
## MANERA DEL USO DE ESTE SOFTWARE, INCLUSO SI SE HA ADVERTIDO DE LA POSIBILIDAD DE
## TALES DAÑOS.
##
## Las opiniones y conclusiones contenidas en el software y la documentación son las
## de los autores y no deben interpretarse como la representación de las políticas
## oficiales, ya sea expresa o implícita, de Fundación Dr. Manuel Sadosky .
##
##  Decifrado de imagenes de Snapchat version 5.0.34.10
##  Author: Joaquín Rinaudo
## 

import subprocess
import shlex
import md5
from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
import json
import time
import os
import base64
import re

def run_get_output(command):
	try:
		return subprocess.check_output(shlex.split(command),stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as grepexc:                                                                                                   
		return grepexc.output

def run_blocking_cmd(command):
	return subprocess.call(shlex.split(command),stdout=subprocess.PIPE,stderr=subprocess.PIPE)

def get_android_id():
	try:
		android_id = run_get_output(''' adb shell content query --uri content://settings/secure --projection name:value --where "name=\\'android_id\\'" ''')
		p = re.compile('Row: 0 name=android_id, value=(.*)')
		android_id = p.findall(android_id)[0].strip()
	except:
		android_id = run_get_output(''' adb shell settings get secure android_id ''').strip()
	print android_id
	return android_id

def get_version():
	version = run_get_output(''' adb shell dumpsys package com.snapchat.android ''') 
	p = re.compile('versionName=(.*)')
	print p.findall(version)[0].strip()
	return p.findall(version)[0].strip()

def pull_bananas_cache_file():
	version38 = ''
	if VERSION >= '5.0.38.1':
		version38 = '1'
	run_blocking_cmd(''' adb pull /data/data/com.snapchat.android/cache/bananas%s encrypted_bananas_file ''' %version38)

def snapchat_bananas_password():
	m = md5()
	m.update( get_android_id() )
	m.update('seems legit...')
	return m.hexdigest()

def decrypt_bananas_file():
	with open("encrypted_bananas_file") as encrypted_bananas:
		with open("decrypted_bananas_file",'w') as decrypted_bananas:
			cipher = AES.new(snapchat_bananas_password(), AES.MODE_ECB)
			decrypt_file(encrypted_bananas,decrypted_bananas,cipher )	

def pull_images():
	run_blocking_cmd(''' adb pull /data/data/com.snapchat.android/cache/received_image_snaps/ encrypted_received_image_snaps/ ''')

def extract_key_and_iv(json_bananas):
	if VERSION < '5.0.38.1':
		key= json_bananas['a']		
		iv= json_bananas['b']
	else: 
		key= json_bananas[0]
		iv= json_bananas[1]
	return (base64.b64decode(key).encode('hex'),base64.b64decode(iv).encode('hex'))

def decrypt_images():
	if not os.path.exists('decrypted_received_image_snaps'): os.makedirs('decrypted_received_image_snaps')
	with open("decrypted_bananas_file") as json_file:
		bananas = json.loads(json_file.read().decode('utf8'))
		if not bananas.get('snapKeysAndIvs',None):
			print "Images were already viewed, the key and IV were deleted from the /cache/bananas file. Try reopening Snapchat to check if images where downloaded."
			exit(0)
		json_bananas = json.loads(bananas['snapKeysAndIvs'],encoding='utf8')
		if len(json_bananas) < len( os.listdir("encrypted_received_image_snaps") ):
			print "There are less keys than snaps, some snaps won't be able to be decrypted"
		for file_name in os.listdir("encrypted_received_image_snaps"):	
			could_decrypt = False
			for snap_pair in json_bananas:
				(key,iv) = extract_key_and_iv( json_bananas[snap_pair] )

				s = run_get_output('openssl aes-128-cbc -K %s -iv %s -d -in encrypted_received_image_snaps/%s -out decrypted_received_image_snaps/%s' %(key,iv,file_name,file_name))
				if s == '':
					could_decrypt = True
					break
					#no error then the image was decoded properly 	
			if not could_decrypt:
				print "The image %s could not be decrypted, none of the keys in the bananas file worked" %file_name
				#break when decrypt work

def decrypt_file(in_file, out_file, cipher):
    bs = AES.block_size
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)

if __name__ == '__main__':
	global VERSION 
	VERSION = get_version()
	#stop the application to save the 'bananas file'
	run_blocking_cmd('adb shell am force-stop com.snapchat.android')
	pull_images()
	pull_bananas_cache_file()
	decrypt_bananas_file()
	decrypt_images()
	#Cleaning up
	run_blocking_cmd('rm encrypted_bananas_file decrypted_bananas_file')
	run_blocking_cmd('rm -r encrypted_received_image_snaps')
