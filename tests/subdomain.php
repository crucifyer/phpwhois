<?php

// $ php composer.phar require "layershifter/tld-extract" "^1.2"

$domain = 'very.sub.domain.github.com';
$extract = new \LayerShifter\TLDExtract\Extract();
$extract->setExtractionMode(\LayerShifter\TLDExtract\Extract::MODE_ALLOW_ICANN);
$parsed = $extract->parse($domain);
$registrableDomain = $parsed->getRegistrableDomain();
echo $registrableDomain, "\n"; // github.com
