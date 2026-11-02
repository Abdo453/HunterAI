<?php
if (isset($_GET['page'])) {
    include($_GET['page']);
} else {
    echo "vulnerable include endpoint\n";
}
