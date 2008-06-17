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

include_once( "lib/ezutils/classes/ezini.php" );
include_once('extension/ezgpg/classes/ezgpgencoder.php');

class eZGPGOperators
{
    /*!
     Constructor
    */
    function eZGPGOperators()
    {
        $this->Operators = array( 'ezgpg_decode', 'ezgpg_decrypt',
                                  'ezgpg_encode', 'ezgpg_encrypt',
                                  'ezgpg_decrypt_limit' );
        $this->Debug = false;
    }

    /*!
     Returns the operators in this class.
    */
    function &operatorList()
    {
        return $this->Operators;
    }

    /*!
     \return true to tell the template engine that the parameter list
    exists per operator type, this is needed for operator classes
    that have multiple operators.
    */
    function namedParameterPerOperator()
    {
        return true;
    }

    /*!
     See eZTemplateOperator::namedParameterList()
    */
    function namedParameterList()
    {
        /*
        return array( 'ezgpg_decrypt' => array( 'data' => array( 'type' => 'string',
                                                                'required' => true,
                                                                'default' => '' ),
                                               'key' => array( 'type' => 'string',
                                                               'required' => true,
                                                               'default' => '' ) ) );
        */

        return array( 'ezgpg_decode' => array( 'data' => array( 'type' => 'string', 'required' => true, 'default' => '' ),
                                             'key' => array( 'type' => 'string', 'required' => true, 'default' => '' )
                                             ),

                      'ezgpg_encode' =>  array( 'data' => array( 'type' => 'string',
                                                              'required' => true,
                                                              'default' => '' ),
                                             'key' => array( 'type' => 'string',
                                                             'required' => true,
                                                             'default' => '' )
                                              ),

                      'ezgpg_decode' => array( 'data' => array( 'type' => 'string',
                                                              'required' => true,
                                                              'default' => '' ),
                                             'key' => array( 'type' => 'string',
                                                             'required' => true,
                                                             'default' => '' )
                                              ),

                      'ezgpg_encrypt' => array( 'data' => array( 'type' => 'string',
                                                               'required' => true,
                                                               'default' => '' ),
                                              'key' => array( 'type' => 'string',
                                                              'required' => true,
                                                              'default' => '' )
                                              ),

                      'ezgpg_decrypt' => array( 'data' => array( 'type' => 'string',
                                                               'required' => true,
                                                               'default' => '' ),
                                              'key' => array( 'type' => 'string',
                                                              'required' => true,
                                                              'default' => '' )
                                              ),

                      'ezgpg_decrypt_limit' => array( 'data' => array( 'type' => 'string',
                                                               'required' => true,
                                                               'default' => '' ),
                                              'key' => array( 'type' => 'string',
                                                              'required' => true,
                                                              'default' => '' )
                                                    )
                      );
    }

    /*!
     \Executes the needed operator(s).
     \Checks operator names, and calls the appropriate functions.
    */
    function modify( &$tpl, &$operatorName, &$operatorParameters, &$rootNamespace,
                     &$currentNamespace, &$operatorValue, &$namedParameters )
    {
        switch ( $operatorName )
        {
            case 'ezgpg_encode':
            case 'ezgpg_encrypt':
            {
                $operatorValue = $this->gpgEncode( $namedParameters['data'], $namedParameters['key'] );
            }
            break;

            case 'ezgpg_decode':
            case 'ezgpg_decrypt':
            {
                $operatorValue = $this->gpgDecode( $namedParameters['data'], $namedParameters['key'] );
            }
            break;

            case 'ezgpg_decrypt_limit':
            {
                // Suggestion: Add parameter - limit (numeric)
                $operatorValue = $this->gpgDecodeLimited( $namedParameters['data'], $namedParameters['key'] );
            }
            break;
        }
    }

    /*!
     \Encodes the data for given key.
    */
    static function gpgEncode( $data, $key )
    {
        // fetch default settings
        $ini = eZINI::instance( 'ezgpg.ini' );

        $gpg_binary = $ini->variable( 'GPGLocations', 'GPGBinary');
        if ( is_array( $gpg_binary ) )
            $gpg_binary = $gpg_binary[eZSys::osType()];
        $gpg_binary = eZDIR::convertSeparators( $gpg_binary, eZDir::SEPARATOR_LOCAL );
        $gpg_keyring = $ini->variable( 'GPGLocations', 'GPGKeyring');

        $gpgEncoder = new GPG( $gpg_binary, $gpg_keyring );
        $encoded_data = $gpgEncoder->encode( $data, $key );

        if ( $encoded_data )
        {
            eZDebug::writeDebug( 'eZGPGOperators::gpgEncode: encoded data: ' . $encoded_data );
        } else {
            eZDebug::writeError( 'eZGPGOperators::gpgEncode: no encoded data returned : ' . $gpgEncoder->errormsg );
        }

        return $encoded_data;
    }

    /*!
     \Decodes the data for given key.
    */
    static function gpgDecode( $data, $key )
    {
        // fetch default settings
        $ini = eZINI::instance( 'ezgpg.ini' );

        $gpg_binary = $ini->variable( 'GPGLocations', 'GPGBinary');
        if ( is_array( $gpg_binary ) )
            $gpg_binary = $gpg_binary[eZSys::osType()];
        $gpg_binary = eZDIR::convertSeparators( $gpg_binary, eZDir::SEPARATOR_LOCAL );
        $gpg_keyring = $ini->variable( 'GPGLocations', 'GPGKeyring');

        $gpgDecoder = new GPG( $gpg_binary, $gpg_keyring );
        $decoded_data = $gpgDecoder->decode( $data, $key );

        if ( $decoded_data !== false )
        {
            $ret = $decoded_data;
            eZDebug::writeDebug( 'eZGPGOperators::gpgDecode: decoded data: ' . $decoded_data );
        } else {
            $ret = false;
            eZDebug::writeError( 'eZGPGOperators::gpgDecodeLimited: no decoded data returned : ' . $gpgDecoder->errormsg );
        }

        return $ret;
    }


    /*!
     \Decodes the data for given key and returns only a limited number of characters.
    */
    static function gpgDecodeLimited( $data, $key, $limit = 4 )
    {
        // fetch default settings
        $ini = eZINI::instance( 'ezgpg.ini' );

        $gpg_binary = $ini->variable( 'GPGLocations', 'GPGBinary');
        if ( is_array( $gpg_binary ) )
            $gpg_binary = $gpg_binary[eZSys::osType()];
        $gpg_binary = eZDIR::convertSeparators( $gpg_binary, eZDir::SEPARATOR_LOCAL );
        $gpg_keyring = $ini->variable( 'GPGLocations', 'GPGKeyring');

        $gpgDecoder = new GPG( $gpg_binary, $gpg_keyring );
        $decoded_data = $gpgDecoder->decode( $data, $key );

        if ( $decoded_data )
        {
            eZDebug::writeDebug( 'eZGPGOperators::gpgDecode: decoded data: ' . $decoded_data );
        } else {
            eZDebug::writeError( 'eZGPGOperators::gpgDecodeLimited: no decoded data returned : ' . $gpgDecoder->errormsg );
        }

        if ( $limit != false )
        {
            $ret = strrev( substr( strrev( $decoded_data ), 0, 4 ) );
        } else {
            $ret = $decoded_data;
        }

        return $ret;
    }

    /// \privatesection
    var $Operators;
}

?>
