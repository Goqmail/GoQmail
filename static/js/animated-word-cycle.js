// Animated Email Provider Word Cycling Effect
document.addEventListener('DOMContentLoaded', function() {
    const animatedWord = document.getElementById('animated-word');
    if (!animatedWord) return;

    const words = ['Gmail', 'Yahoo', 'Outlook', 'ProtonMail', 'iCloud'];
    let currentIndex = 0;

    function cycleWords() {
        // Start fade out
        animatedWord.classList.add('fade-out');
        
        // After the fade out animation completes, change the word and fade in
        setTimeout(function() {
            currentIndex = (currentIndex + 1) % words.length;
            animatedWord.textContent = words[currentIndex];
            animatedWord.classList.remove('fade-out');
            animatedWord.classList.add('fade-in');
            
            // Remove the fade-in class after animation completes
            setTimeout(function() {
                animatedWord.classList.remove('fade-in');
            }, 400);
        }, 400);
    }

    // Start the word cycling
    setInterval(cycleWords, 3000);
});