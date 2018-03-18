<?php
/**
 *  UltimateBotKiller - PHP Library For Block 99.99% of Malicious Bots.
 *
 *  @author Alemalakra
 *  @version 3.0
 */

// Load class, and load it.
require('src/ultimatebotkiller.php');
$UBK = new Alemalakra\UltimateBotKiller\UBK();

// Check if post is set.
if ($UBK->validateForm()) {
	if ($UBK->getValueInput("somepostinput")) {
		echo 'Post validated without errors!';
	}
}

// Encrypt JavaScript Code.
for ($i = 0; $i < rand(3, 10); $i++) {
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
// After check if the form was sent.
$FormInput1 = $UBK->getNameInput('somepostinput');
?>
<center>
	<form method="post">
		Sample Input:
		<input type="text" name="<?php echo $FormInput1; ?>" value="Any form input" />
		<?php echo $UBK->getInputBotKiller($_s); ?>
		<button type="submit">Submit Form POST</button>
	</form>
</center>
