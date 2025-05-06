import React, { useEffect } from 'react';
import { Shield, Clock, Activity, Users, ChevronDown, ArrowRight, Github, Twitter, Linkedin, ArrowDown } from 'lucide-react';
import { useNavigate, Link } from 'react-router-dom';
import { motion, useScroll, useTransform } from 'framer-motion';

const features = [
  {
    icon: Shield,
    title: 'End-to-End Encryption',
    description: 'Your documents are protected with military-grade AES-256 encryption, ensuring complete privacy and security.',
  },
  {
    icon: Clock,
    title: 'Expiring Shared Links',
    description: 'Set automatic expiration dates for shared documents to maintain control over sensitive information.',
  },
  {
    icon: Activity,
    title: 'Activity Audit Logs',
    description: 'Track every interaction with your documents through detailed audit trails and activity monitoring.',
  },
  {
    icon: Users,
    title: 'Role-Based Access',
    description: 'Define precise access levels and permissions for team members and external collaborators.',
  },
];

const testimonials = [
  {
    name: 'Sara Srifi',
    role: 'CEO at EKKO',
    image: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?auto=format&fit=crop&w=100&h=100',
    quote: 'Elysian Vault has transformed how we handle sensitive client documents. The security features are unmatched.',
  },
  {
    name: 'Marcus Rodriguez',
    role: 'Legal Director',
    image: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?auto=format&fit=crop&w=100&h=100',
    quote: 'The intuitive interface and robust security features make Elysian Vault our go-to platform for document sharing.',
  },
];

const faqs = [
  {
    question: 'How secure is Elysian Vault?',
    answer: 'We use AES-256 encryption for all stored documents and implement zero-knowledge encryption. Your files are encrypted before they leave your device, ensuring only authorized users can access them.',
  },
  {
    question: 'What are the pricing plans?',
    answer: 'We offer flexible plans starting from $9.99/month for individuals, with team and enterprise options available. All plans include our core security features.',
  },
  {
    question: 'Can I control who accesses my documents?',
    answer: 'Yes, you have complete control over document access. Set specific permissions, require password protection, and implement expiring links for temporary access.',
  },
];

export function LandingPage() {
  const [openFaq, setOpenFaq] = React.useState<number | null>(null);
  const navigate = useNavigate();
  const { scrollYProgress } = useScroll();
  const opacity = useTransform(scrollYProgress, [0, 0.05], [1, 0]);
  
  useEffect(() => {
    // Smooth scroll to sections when clicking navigation
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', function(this: HTMLAnchorElement, e: Event) {
        e.preventDefault();
        const href = this.getAttribute('href');
        if (!href) return;
        const target = document.querySelector(href);
        if (!target) return;
        target.scrollIntoView({
          behavior: 'smooth'
        });
      });
    });
  }, []);

  return (
    <div className="min-h-screen bg-white">
      {/* Modern fixed navigation */}
      <header className="fixed w-full z-50 bg-white/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <div className="text-2xl font-display font-bold bg-gradient-to-r from-primary-600 to-secondary-500 bg-clip-text text-transparent">
              Elysian Vault
            </div>
            
            <nav className="hidden md:flex space-x-8">
              <a href="#features" className="text-neutral-700 hover:text-primary-600 font-medium">Features</a>
              <a href="#testimonials" className="text-neutral-700 hover:text-primary-600 font-medium">Testimonials</a>
              <a href="#faq" className="text-neutral-700 hover:text-primary-600 font-medium">FAQ</a>
            </nav>
            
            <div className="flex space-x-4">
              <Link to="/login" className="text-neutral-700 hover:text-primary-600 font-medium">
                Login
              </Link>
              <Link to="/login" className="bg-neutral-900 text-white px-4 py-2 rounded-md font-medium hover:bg-neutral-800">
                Get Started
              </Link>
            </div>
          </div>
        </div>
      </header>
      
      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center pt-20">
        <div className="absolute inset-0 z-0">
          <img 
            src="https://images.unsplash.com/photo-1566041510639-8d95a2490bfb?auto=format&fit=crop&q=80"
            alt="Background" 
            className="w-full h-full object-cover"
          />
          <div className="absolute inset-0 bg-black/50"></div>
        </div>
        
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-32 relative z-10">
          <div className="max-w-4xl">
            <motion.h1 
              className="text-6xl md:text-7xl font-bold font-display mb-6 text-white"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
            >
              Security Without Compromise
            </motion.h1>
            
            <motion.p 
              className="text-xl md:text-2xl text-white/80 mb-8 max-w-2xl"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.2 }}
            >
              Elysian Vault provides military-grade encryption for seamless and secure document collaboration.
            </motion.p>
            
            <motion.div 
              className="flex flex-col sm:flex-row gap-4"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.4 }}
            >
              <button
                className="bg-white text-neutral-900 hover:bg-white/90 px-8 py-4 rounded-md font-medium text-lg transition-all duration-300"
                onClick={() => navigate('/login')}
              >
                Get Started
                <ArrowRight className="ml-2 w-5 h-5 inline" />
              </button>
              
              <Link 
                to="/login" 
                className="border border-white text-white px-8 py-4 rounded-md font-medium text-lg hover:bg-white/10 transition-all duration-300"
              >
                Login
              </Link>
            </motion.div>
          </div>
        </div>
        
        <motion.a 
          href="#features"
          className="absolute bottom-10 left-1/2 transform -translate-x-1/2 z-10 text-white"
          style={{ opacity }}
          animate={{ y: [0, 10, 0] }}
          transition={{ repeat: Infinity, duration: 2 }}
        >
          <ArrowDown className="w-8 h-8" />
        </motion.a>
      </section>

      {/* Features Section */}
      <section id="features" className="py-32 bg-neutral-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div 
            className="text-center mb-24"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
          >
            <h2 className="text-4xl font-bold font-display mb-4 text-white">
              Enterprise-Grade Security
            </h2>
            <p className="text-xl text-neutral-400 max-w-2xl mx-auto">
              Our platform provides the highest level of security for your sensitive documents.
            </p>
          </motion.div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                className="bg-neutral-800/50 p-8 rounded-lg backdrop-blur-sm border border-neutral-700"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.8, delay: index * 0.1 }}
              >
                <div className="w-16 h-16 rounded-full bg-primary-500/20 flex items-center justify-center mb-6">
                  <feature.icon className="w-8 h-8 text-primary-500" />
                </div>
                <h3 className="text-2xl font-semibold mb-4 text-white">{feature.title}</h3>
                <p className="text-neutral-400">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
      
      {/* Image section */}
      <section className="py-24 relative bg-neutral-100 overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-16 items-center">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.8 }}
            >
              <h2 className="text-3xl md:text-4xl font-bold font-display mb-6 text-neutral-900">
                Security at the core of everything we do
              </h2>
              <p className="text-lg text-neutral-700 mb-8">
                Every file uploaded to Elysian Vault is secured with end-to-end encryption, ensuring that only you and your authorized collaborators can access your sensitive information.
              </p>
              <ul className="space-y-4">
                {[
                  'Zero-knowledge architecture',
                  'End-to-end encryption',
                  'Compliant with industry standards',
                  'Regular security audits'
                ].map((item, i) => (
                  <motion.li 
                    key={i}
                    className="flex items-center text-neutral-800"
                    initial={{ opacity: 0, x: -10 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.4, delay: 0.1 * i }}
                  >
                    <Shield className="w-5 h-5 mr-2 text-primary-600" />
                    {item}
                  </motion.li>
                ))}
              </ul>
            </motion.div>
            
            <motion.div
              className="rounded-lg overflow-hidden shadow-2xl"
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.8 }}
            >
              <img
                src="https://images.unsplash.com/photo-1557597774-9d273605dfa9?auto=format&fit=crop&q=80"
                alt="Secure document sharing"
                className="w-full h-full object-cover"
              />
            </motion.div>
          </div>
        </div>
        
        <div className="absolute -top-24 -right-24 w-64 h-64 bg-primary-500/10 rounded-full blur-3xl z-0"></div>
        <div className="absolute -bottom-32 -left-32 w-96 h-96 bg-secondary-500/10 rounded-full blur-3xl z-0"></div>
      </section>

      {/* Testimonials */}
      <section id="testimonials" className="py-32 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div 
            className="text-center mb-24"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
          >
            <h2 className="text-4xl font-bold font-display mb-4 text-neutral-900">
              Trusted by Industry Leaders
            </h2>
            <p className="text-xl text-neutral-600 max-w-2xl mx-auto">
              See what our customers have to say about the Elysian Vault experience.
            </p>
          </motion.div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
            {testimonials.map((testimonial, index) => (
              <motion.div
                key={testimonial.name}
                className="bg-white p-8 rounded-lg shadow-xl border border-neutral-100"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.8, delay: index * 0.2 }}
              >
                <p className="text-xl italic mb-8 text-neutral-600">"{testimonial.quote}"</p>
                <div className="flex items-center">
                  <img
                    src={testimonial.image}
                    alt={testimonial.name}
                    className="w-14 h-14 rounded-full object-cover border-2 border-neutral-100"
                  />
                  <div className="ml-4">
                    <h4 className="font-semibold text-lg text-neutral-900">{testimonial.name}</h4>
                    <p className="text-neutral-500">{testimonial.role}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section id="faq" className="py-32 bg-neutral-900">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div 
            className="text-center mb-24"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
          >
            <h2 className="text-4xl font-bold font-display mb-4 text-white">
              Frequently Asked Questions
            </h2>
            <p className="text-xl text-neutral-400 max-w-2xl mx-auto">
              Find answers to common questions about Elysian Vault.
            </p>
          </motion.div>
          
          <div className="space-y-6">
            {faqs.map((faq, index) => (
              <motion.div
                key={index}
                className="overflow-hidden"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
              >
                <button
                  className="w-full py-6 text-left flex justify-between items-center border-b border-neutral-700"
                  onClick={() => setOpenFaq(openFaq === index ? null : index)}
                >
                  <span className="text-xl font-medium text-white">{faq.question}</span>
                  <motion.div
                    animate={{ rotate: openFaq === index ? 180 : 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <ChevronDown className="w-6 h-6 text-primary-500" />
                  </motion.div>
                </button>
                
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ 
                    height: openFaq === index ? 'auto' : 0,
                    opacity: openFaq === index ? 1 : 0
                  }}
                  transition={{ duration: 0.3 }}
                  className="overflow-hidden"
                >
                  <div className="py-6 text-neutral-400">
                    {faq.answer}
                  </div>
                </motion.div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
      
      {/* Call to action */}
      <section className="py-24 bg-primary-600">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.h2 
            className="text-3xl md:text-4xl font-bold font-display text-white mb-6"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
          >
            Ready to secure your documents?
          </motion.h2>
          
          <motion.p 
            className="text-xl text-white/80 mb-8 max-w-2xl mx-auto"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8, delay: 0.1 }}
          >
            Join thousands of professionals who trust Elysian Vault with their sensitive data.
          </motion.p>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8, delay: 0.2 }}
          >
            <button
              className="bg-white text-primary-600 hover:bg-white/90 px-8 py-4 rounded-md font-medium text-lg transition-all duration-300"
              onClick={() => navigate('/login')}
            >
              Start Secure Sharing
              <ArrowRight className="ml-2 w-5 h-5 inline" />
            </button>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-neutral-900 border-t border-neutral-800 py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-12">
            <div className="col-span-1 md:col-span-2">
              <h3 className="text-2xl font-display font-bold text-white mb-6">Elysian Vault</h3>
              <p className="text-neutral-400 mb-6 max-w-md">
                Secure document sharing for modern businesses. Advanced encryption, access controls, and collaboration features in one platform.
              </p>
              <div className="flex space-x-4">
                <a
                  href="#"
                  className="text-neutral-400 hover:text-white transition-colors"
                  aria-label="GitHub"
                >
                  <Github className="w-6 h-6" />
                </a>
                <a
                  href="#"
                  className="text-neutral-400 hover:text-white transition-colors"
                  aria-label="Twitter"
                >
                  <Twitter className="w-6 h-6" />
                </a>
                <a
                  href="#"
                  className="text-neutral-400 hover:text-white transition-colors"
                  aria-label="LinkedIn"
                >
                  <Linkedin className="w-6 h-6" />
                </a>
              </div>
            </div>
            
            <div>
              <h4 className="text-lg font-semibold text-white mb-6">Product</h4>
              <ul className="space-y-4">
                <li>
                  <a href="#features" className="text-neutral-400 hover:text-white transition-colors">Features</a>
                </li>
                <li>
                  <a href="#" className="text-neutral-400 hover:text-white transition-colors">Security</a>
                </li>
                <li>
                  <a href="#" className="text-neutral-400 hover:text-white transition-colors">Enterprise</a>
                </li>
                <li>
                  <a href="#" className="text-neutral-400 hover:text-white transition-colors">Pricing</a>
                </li>
              </ul>
            </div>
            
            <div>
              <h4 className="text-lg font-semibold text-white mb-6">Legal</h4>
              <ul className="space-y-4">
                <li>
                  <a href="#" className="text-neutral-400 hover:text-white transition-colors">Privacy Policy</a>
                </li>
                <li>
                  <a href="#" className="text-neutral-400 hover:text-white transition-colors">Terms of Service</a>
                </li>
                <li>
                  <a href="#" className="text-neutral-400 hover:text-white transition-colors">Security Policy</a>
                </li>
                <li>
                  <a href="#" className="text-neutral-400 hover:text-white transition-colors">GDPR Compliance</a>
                </li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-neutral-800 mt-16 pt-8 text-neutral-500 text-sm">
            <p>© 2025 Elysian Vault. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}