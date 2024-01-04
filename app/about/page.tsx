const AboutPage = () => {
    return (
        <main className="flex-grow container mx-auto p-4">
        <section className="text-center my-8">
          <h1 className="text-4xl font-bold text-slate-200">Hello, I'm Irfan/Capang</h1>
          <p className="text-slate-200 mt-4">A Student for Life</p>
        </section>

        <section className="my-8">
          <h2 className="text-3xl font-bold text-slate-200">Education</h2>
          <div className="text-slate-300 mt-4 space-y-4">
            <p><strong>Bachelor of Computer Science Majoring in Computer Systems and Networking</strong> University of Malaya (July 2025)</p>
            <p><strong>Undergraduate Exchange Student</strong> University of Tokyo (March 2024)</p>
            <p><strong>Foundation in Physical Sciences</strong> University of Malaya </p>
          </div>
        </section>

        <section className="my-8">
          <h2 className="text-3xl font-bold text-slate-200">My Learning Journey</h2>
          <div className="text-slate-300 mt-4 space-y-4">
            <p><strong>Introduction to Networking by CISCO:</strong> Completed a comprehensive introduction to networking course provided by CISCO.</p>
            <p><strong>SRWE (Switching, Routing, and Wireless Essentials) by CISCO:</strong> Focused on essential skills in switching, routing, and wireless technologies.</p>
            <p><strong>Cisco CyberOps:</strong> Attained certification in CyberOps, emphasizing practical skills in cybersecurity operations.</p>
            <p><strong>Network Security by Cisco:</strong> Gained expertise in securing network infrastructure and data.</p>
            <p><strong>ENSA (Enterprise Networking, Security, and Automation) by CISCO:</strong> Acquired skills in enterprise networking, security, and automation.</p>
            <p><strong>Self-Learning in Cybersecurity:</strong> Engaged in self-learning, exploring various concepts, tools, and techniques in cybersecurity.</p>
            <p><strong>Capture The Flag (CTF) Competitions:</strong> Participated in CTF competitions, focusing on PWN/BinEx category.</p>
          </div>
        </section>

        {/* Additional content sections can be added here */}
        </main>
    );
}
export default AboutPage;