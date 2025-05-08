document.addEventListener('DOMContentLoaded', () => {
    // Animate cards on scroll
    const animateOnScroll = () => {
        const cards = document.querySelectorAll('.card');
        const windowHeight = window.innerHeight;
        
        cards.forEach((card, index) => {
            const cardPosition = card.getBoundingClientRect().top;
            const animationDelay = index * 0.1;
            
            if (cardPosition < windowHeight - 100) {
                setTimeout(() => {
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }, animationDelay * 1000);
            }
        });
    };
    
    // Initial animation
    animateOnScroll();
    
    // Animate on scroll
    window.addEventListener('scroll', animateOnScroll);
    
    // Add particles effect
    const createParticles = () => {
        const particlesContainer = document.querySelector('.particles');
        const particleCount = 50;
        
        for (let i = 0; i < particleCount; i++) {
            const particle = document.createElement('div');
            particle.classList.add('particle');
            
            // Random properties
            const size = Math.random() * 5 + 1;
            const posX = Math.random() * 100;
            const posY = Math.random() * 100;
            const delay = Math.random() * 5;
            const duration = Math.random() * 10 + 5;
            
            particle.style.width = `${size}px`;
            particle.style.height = `${size}px`;
            particle.style.left = `${posX}%`;
            particle.style.top = `${posY}%`;
            particle.style.animationDelay = `${delay}s`;
            particle.style.animationDuration = `${duration}s`;
            particle.style.opacity = Math.random() * 0.5 + 0.1;
            
            particlesContainer.appendChild(particle);
        }
    };
    
    createParticles();
    
    // Button hover effect enhancement
    const buttons = document.querySelectorAll('.button');
    buttons.forEach(button => {
        button.addEventListener('mousemove', (e) => {
            const rect = button.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            button.style.setProperty('--mouse-x', `${x}px`);
            button.style.setProperty('--mouse-y', `${y}px`);
        });
    });
});
