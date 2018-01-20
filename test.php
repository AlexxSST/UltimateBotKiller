<?php
/**
 *  UltimateBotKiller - PHP Library For Block 99.99% of Malicious Bots.
 *
 *  @author Alemalakra
 *  @version 2.0
 */

// Load class, and load it.
require('src/ultimatebotkiller.php');
$UBK = new Alemalakra\UltimateBotKiller\UBK();

// Check if post is set.
if ($UBK->validateForm()) {
	echo 'Post validated without errors!';
}

// Encrypt JavaScript Code.
for ($i=0; $i < rand(3,10); $i++) {
	if (isset($_s)) {
		$tmp = new Packer($_s, 'Normal', true, false, true);
		$tmp = $tmp->pack();
		$_s = $tmp;
		unset($tmp);
	} else {
		$_s = new Packer($UBK->getCode(), 'Normal', true, false, true);
		$_s = $_s->pack();
		$_s = $_j->ubk($_s);
	}
}
?>
<center>
	<form method="post">
		Sample Input: <input type="text" name="someinput" value="Any form input" />
		<?php echo $UBK->getInput($_s); ?>
		<button type="submit">Submit Form POST</button>
	</form>
</center>
