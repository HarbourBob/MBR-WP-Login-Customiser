jQuery(document).ready(function($) {
    
    // Initialize color pickers
    $('.color-picker').wpColorPicker();
    
    // Media uploader for logo
    var logoUploader;
    $('#upload_logo_button').on('click', function(e) {
        e.preventDefault();
        
        // If the uploader object has already been created, reopen the dialog
        if (logoUploader) {
            logoUploader.open();
            return;
        }
        
        // Create the media uploader
        logoUploader = wp.media({
            title: 'Choose Logo',
            button: {
                text: 'Use this logo'
            },
            multiple: false,
            library: {
                type: 'image'
            }
        });
        
        // When an image is selected, update the field and preview
        logoUploader.on('select', function() {
            var attachment = logoUploader.state().get('selection').first().toJSON();
            $('#mbr_custom_login_logo').val(attachment.url);
            
            // Update preview
            var preview = '<img src="' + attachment.url + '" style="max-width: 320px; max-height: 100px; display: block; margin-bottom: 10px;">';
            $('#logo-preview').html(preview);
            $('#remove_logo_button').show();
        });
        
        // Open the uploader dialog
        logoUploader.open();
    });
    
    // Remove logo button
    $('#remove_logo_button').on('click', function(e) {
        e.preventDefault();
        $('#mbr_custom_login_logo').val('');
        $('#logo-preview').html('');
        $(this).hide();
    });
    
    // Media uploader for background image
    var bgImageUploader;
    $('#upload_bg_image_button').on('click', function(e) {
        e.preventDefault();
        
        // If the uploader object has already been created, reopen the dialog
        if (bgImageUploader) {
            bgImageUploader.open();
            return;
        }
        
        // Create the media uploader
        bgImageUploader = wp.media({
            title: 'Choose Background Image',
            button: {
                text: 'Use this image'
            },
            multiple: false,
            library: {
                type: 'image'
            }
        });
        
        // When an image is selected, update the field and preview
        bgImageUploader.on('select', function() {
            var attachment = bgImageUploader.state().get('selection').first().toJSON();
            $('#mbr_custom_login_bg_image').val(attachment.url);
            
            // Update preview
            var preview = '<img src="' + attachment.url + '" style="max-width: 400px; max-height: 200px; display: block; margin-bottom: 10px;">';
            $('#bg-image-preview').html(preview);
            $('#remove_bg_image_button').show();
        });
        
        // Open the uploader dialog
        bgImageUploader.open();
    });
    
    // Remove background image button
    $('#remove_bg_image_button').on('click', function(e) {
        e.preventDefault();
        $('#mbr_custom_login_bg_image').val('');
        $('#bg-image-preview').html('');
        $(this).hide();
    });
    
    // Background type radio button handler
    $('.bg-type-radio').on('change', function() {
        var selectedType = $(this).val();
        
        // Hide all background option rows
        $('.bg-option').hide();
        
        // Show relevant rows based on selected type
        if (selectedType === 'color') {
            $('.bg-color').show();
        } else if (selectedType === 'gradient') {
            $('.bg-gradient').show();
        } else if (selectedType === 'image') {
            $('.bg-image').show();
        }
    });
    
    // Generate emergency key button handler
    $(document).on('click', 'button[onclick*="mbr_custom_login_emergency_key"]', function(e) {
        // This is handled inline in the PHP, but we can enhance it
        setTimeout(function() {
            alert('New emergency key generated! Make sure to save your settings.');
        }, 100);
    });
});
