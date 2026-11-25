<?php
$page = $_GET['page'] ?? 'home';
eval($page);
include($_GET['template']);
