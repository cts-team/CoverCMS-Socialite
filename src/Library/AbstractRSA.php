<?php


namespace CoverCMS\Socialite\Library;


abstract class AbstractRSA
{
    public static function parseKey($key)
    {
        return wordwrap(preg_replace('/[\r\n]/', '', $key), 64, "\n", true);
    }
}