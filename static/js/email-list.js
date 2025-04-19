document.addEventListener('DOMContentLoaded', function() {
    // Variables for elements 
    const emailListItems = document.querySelectorAll('.email-list-item');
    const emailDetailSidebar = document.querySelector('.email-detail-sidebar');
    
    // Handle email list item click
    emailListItems.forEach(item => {
        item.addEventListener('click', function() {
            // Reset all items to default state
            emailListItems.forEach(el => {
                el.classList.remove('active');
            });
            
            // Add active class to clicked item
            this.classList.add('active');
            
            // Show right sidebar on larger screens
            if (window.innerWidth >= 992) {
                emailDetailSidebar.classList.add('active');
            }
        });
    });
    
    // Collapse functionality is handled by Bootstrap's collapse component
    
    // Handle responsive navbar toggle
    const sidebarToggle = document.createElement('button');
    sidebarToggle.className = 'sidebar-toggle btn btn-outline-light btn-sm position-fixed';
    sidebarToggle.style.top = '70px';
    sidebarToggle.style.left = '10px';
    sidebarToggle.style.zIndex = '1050';
    sidebarToggle.style.display = 'none';
    sidebarToggle.innerHTML = '<i class="bi bi-list"></i>';
    document.body.appendChild(sidebarToggle);
    
    const emailSidebar = document.querySelector('.email-sidebar');
    
    sidebarToggle.addEventListener('click', function() {
        emailSidebar.classList.toggle('active');
    });
    
    // Responsive behavior
    function checkScreenSize() {
        if (window.innerWidth < 768) {
            sidebarToggle.style.display = 'block';
        } else {
            sidebarToggle.style.display = 'none';
            emailSidebar.classList.remove('active');
        }
    }
    
    // Initial check and add resize listener
    checkScreenSize();
    window.addEventListener('resize', checkScreenSize);
});
