<?php
//
// Created on: <12-Jan-2007 12:57:54 gb>
//
// Copyright (C) 2001-2006 Brookins Consulting. All rights reserved.
//
// This file may be distributed and/or modified under the terms of the
// "GNU General Public License" version 2 or greater as published by the Free
// Software Foundation and appearing in the file LICENSE.GPL included in
// the packaging of this file.
//
// This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING
// THE WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE.
//
// The "GNU General Public License" (GPL) is available at
// http://www.gnu.org/copyleft/gpl.html.
//
// Contact licence@brookinsconsulting.com if any conditions of
// this licencing isn't clear to you.
//


/**
 * PHP GPG Class
 *
 * This PHP class takes any number of PGP or GPG keys that are available via a
 * public GPG keyring on a webserver, and encrypts the submitted block of
 * information to those keys.  There is error checking to make sure that the
 * submitted keys are valid.
 *
 * PHP version 4
 *
 * Original author: Nathan Ho
 * Original source: http://www.theoslogic.com/scripts/php-gpg/
 * Original licence: "Right are hereby granted for you to use this script however you want."
 * Bugs fixed & modified for use in eZ publish: Zurgutt <zurgutt@gg.ee>
 *
 *
**/

class GPG
{

    /*------{ PROPERTY DECLARATIONS }-------------------------------------*/

    // holds the location of the GPG keyring files
    // default value is "{DOCUMENT_ROOT}/.gnupg"
    var $keyring;

    // holds the GPG binary path
    var $gpgbin     = "/usr/bin/gpg";

    // sets up the command to validate the GPG / PGP keys
    var $gpgck_parm;

    // sets up the command for encrypting the data to the valid keys
    var $gpgcmd_parm;

    // holds a temporary file name for the encrypted data
    var $tmpfile;

    // holds error message in case of error
    var $errormsg;


    /*------{ METHOD DECLARATIONS }---------------------------------------*/

    // constructor function
    // Parameters: path to gpg binary, path to keyring files, directory for temporary file.
    function GPG( $gpgbin, $keyring, $tempdir )
    {

        // set the directory for the GPG keys
        $this->keyring = $keyring;
        // set gpg binary
        $this->gpgbin = $gpgbin;

        // temporary file name - will only hold encrypted data
        $this->tmpfile   = $tempdir . '/' . substr( md5( microtime() ), 7, 10 ).".asc";

        // for validating submitted PGP / GPG key(s)
        $this->gpgck_parm     = " --no-secmem-warning --homedir ".$this->keyring." --list-keys ";

        // for encrypting the data block to the submitted PGP / GPG key(s)
        $this->gpgcmd_parm    = " -a --always-trust --batch --no-secmem-warning --homedir ".$this->keyring." -e -o ".$this->tmpfile;

        // for encrypting the data block to the submitted PGP / GPG key(s)
        // $this->gpg_decrypt_cmd_parm    = " -a --always-trust --batch --no-secmem-warning --homedir ".$this->keyring; // ." -e -o ".$this->tmpfile;
        $this->gpg_decrypt_cmd_parm  = " --passphrase-fd 3 -q --homedir ".$this->keyring." --armor --no-tty --no-permission-warning --no-secmem-warning --no-greeting --decrypt";
    }

    function decode( $data, $key, $debug = false )
    {
        $ret = false;
        $decrypted = '';

        // first, validate the submitted key(s)
        if( !$this->validate_key( $key ) )
        {
                // return eZerror here and else notice

                // Invalid key.
                return FALSE;
        } else {
            // return eZerror here and else notice
        }

        // flatten string
        /*
        foreach( $data as $line )
        {
            $data .= str_replace("\r\n", "", $line);
        }
        */

        // okay - we have valid key.  Let's encrypt the contents now.
        $gpg_call = $this->gpgbin . " --recipient $key " . $this->gpg_decrypt_cmd_parm;
        $gpg_call .= " 3<<< '$key' <<< '$data' ";

        // $last_line = system( $gpg_call, $decrypted );
        // $decrypted = passthru( $gpg_call, $retcode );
        // $decrypted = passthru( $gpg_call, $retcode );

        /* Add redirection so we can get stderr. */
        $handle = popen($gpg_call, 'r');
        $decrypted = fread($handle, 2096);

        /*
        print_r('command: '. $gpg_call .'<hr />');
        print_r( $ret .'<hr />');
        die();
        */

        // Debug
        if( $debug == true )
        {
           print_r('command: '. $gpg_call .'<hr />');
           print_r( $ret .'<hr />');
           die();
        }

        if( !$decrypted )
        {
                $this->errormsg = "Failure connecting to gpg binary: '$gpg_call'.";
                return FALSE;
        } else {
            $ret = $decrypted;
        }

        return $ret;
    }

    function encode( $data, $key, $debug = false )
    {
        // first, validate the submitted key(s)
        if( !$this->validate_key( $key ) )
        {
            // Invalid key.
            return FALSE;
        }

        // okay - we have valid key.  Let's encrypt the contents now.
        $gpg_call = $this->gpgbin . " --recipient $key " . $this->gpgcmd_parm;
        $handle = popen( $gpg_call, "w" );
        if( !$handle )
        {
            $this->errormsg = "Failure connecting to gpg binary: '$gpg_call'.";
            return FALSE;

        }

        // Debug
        if( $debug == true )
        {
            print_r('command: '. $gpg_call .'<hr />');
            print_r( $ret .'<hr />');
            // die();
        }

        // we only write the unencrypted data directly to the GPG process, and not to a file
        // Note: Remove disk element as requirired only method supported (re: ezgpg.php has this)
        fwrite( $handle, $data );
        pclose( $handle );
        $encrypted = file_get_contents( $this->tmpfile );
        unlink( $this->tmpfile );

        if( false )
        {
            $encrypted = str_replace("\n", "", $encrypted);
            $encrypted = str_replace("-----BEGIN PGP MESSAGE-----", "-----BEGIN PGP MESSAGE----- ", $encrypted);
            $encrypted = str_replace("-----END PGP MESSAGE-----", " -----END PGP MESSAGE-----", $encrypted);
            $encrypted = str_replace("(GNU/Linux)", "(GNU/Linux) ", $encrypted);
        }
        // die(str_replace("\n", "", $encrypted));

        return $encrypted;
    }

    function validate_key( $key )
    {
        $check_call = $this->gpgbin . $this->gpgck_parm . $key;
        $check_this = shell_exec( $check_call );
        eZDebug::writeNotice( 'eZGPG::validate_key: ' . $check_call );
        eZDebug::writeNotice( 'eZGPG::validate_key result: ' . $check_this );
        if ( ! strstr( $check_this, "pub" ) )
        {
            // Invalid key.
            $this->errormsg = "Invalid key: '$key'.";
            return FALSE;
        }

        return TRUE;
    }

}

?>

